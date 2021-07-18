use std::{
    future::Future,
    io,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use futures::ready;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_io_timeout::TimeoutReader;

#[derive(Debug)]
struct CopyBuffer {
    buf: Box<[u8]>,

    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
}

impl CopyBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0; 4096].into_boxed_slice(),

            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            if self.pos == self.cap && !self.read_done {
                let mut buf = ReadBuf::new(&mut self.buf);
                ready!(reader.as_mut().poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            while self.pos < self.cap {
                let i = ready!(writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero bytes into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

#[derive(Debug)]
struct Copy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    buffer: CopyBuffer,
}

impl<R, W> Future for Copy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;

        me.buffer
            .poll_copy(cx, Pin::new(me.reader), Pin::new(me.writer))
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

pin_project! {
    #[project = CopyBidirectionalProj]
    struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
        #[pin]
        a: TimeoutReader<&'a mut A>,
        #[pin]
        b: TimeoutReader<&'a mut B>,

        a_to_b: TransferState,
        b_to_a: TransferState
    }
}

fn transfer_one_direction<A, B>(
    cx: &mut task::Context<'_>,
    state: &mut TransferState,
    mut r: Pin<&mut TimeoutReader<&mut A>>,
    mut w: Pin<&mut TimeoutReader<&mut B>>,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    loop {
        match state {
            TransferState::Running(buf) => {
                let n = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(n)
            }
            TransferState::ShuttingDown(n) => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done(*n);
            }
            TransferState::Done(n) => return Poll::Ready(Ok(*n)),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectionalProj {
            mut a,
            mut b,
            a_to_b,
            b_to_a,
        } = self.project();

        let poll_a_to_b = transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut())?;
        let poll_b_to_a = transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut())?;

        const READ_TIMEOUT_WHEN_ONE_SHUTDOWN: Duration = Duration::from_secs(5);

        match (poll_a_to_b, poll_b_to_a) {
            (Poll::Ready(a_to_b), Poll::Ready(b_to_a)) => Poll::Ready(Ok((a_to_b, b_to_a))),
            (Poll::Ready(a_to_b), Poll::Pending) => {
                if b.timeout().is_none() {
                    b.as_mut()
                        .set_timeout_pinned(Some(READ_TIMEOUT_WHEN_ONE_SHUTDOWN));
                    let b_to_a =
                        ready!(transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut())?);
                    Poll::Ready(Ok((a_to_b, b_to_a)))
                } else {
                    Poll::Pending
                }
            }
            (Poll::Pending, Poll::Ready(b_to_a)) => {
                if a.timeout().is_none() {
                    a.as_mut()
                        .set_timeout_pinned(Some(READ_TIMEOUT_WHEN_ONE_SHUTDOWN));
                    let a_to_b =
                        ready!(transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut())?);
                    Poll::Ready(Ok((a_to_b, b_to_a)))
                } else {
                    Poll::Pending
                }
            }
            _ => Poll::Pending,
        }
    }
}

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a: TimeoutReader::new(a),
        b: TimeoutReader::new(b),
        a_to_b: TransferState::Running(CopyBuffer::new()),
        b_to_a: TransferState::Running(CopyBuffer::new()),
    }
    .await
}
