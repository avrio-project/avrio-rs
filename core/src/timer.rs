use std::{
    sync::Mutex,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// provides a method to make functions be called after x milliseconds

pub fn create_timer<A: 'static>(duration: Duration, callback: Box<dyn Fn(A) + Send>, params: A)
where
    A: Send,
{
    thread::spawn(move || {
        debug!(
            "Created timer, executes_at={}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_millis()
                + duration.as_millis()
        );
        thread::sleep(duration);
        (callback)(params)
    });
}
