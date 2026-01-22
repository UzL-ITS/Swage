use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

/// A thread handle that can be signaled to stop.
///
/// Wraps a join handle with a cancellation flag that the thread
/// can check to determine when to exit.
pub struct CancelableJoinHandle<T> {
    handle: thread::JoinHandle<T>,
    running: Arc<AtomicBool>,
}

/// Spawns a cancelable thread that can be joined later.
/// The thread is passed an `Arc<AtomicBool>` that can be used to check if the thread should stop running.
/// The thread is requested to stop running when the `AtomicBool` is set to `false`.
pub fn spawn_cancelable<T: Send + Sync + 'static>(
    func: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
) -> CancelableJoinHandle<T> {
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    let handle = thread::spawn(move || func(r));
    CancelableJoinHandle { handle, running }
}

impl<T> CancelableJoinHandle<T> {
    /// Checks if the thread should continue running.
    ///
    /// # Returns
    ///
    /// `true` if thread has not been signaled to stop
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    /// Signals the thread to stop and waits for it to finish.
    ///
    /// # Errors
    ///
    /// Returns error if thread panicked
    pub fn join(self) -> thread::Result<T> {
        self.running.store(false, Ordering::Relaxed);
        self.handle.join()
    }
}
