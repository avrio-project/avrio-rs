// Provides a generic system to allow callbacks

use std::marker::PhantomData;

pub struct Callback<P, CB, O>
where
    CB: Fn(P) -> O,
    O: Send,
{
    callback: Box<CB>,
    _data: PhantomData<P>,
}

impl<P, CB, O> Callback<P, CB, O>
where
    CB: Fn(P) -> O,
    O: Send,
{
    pub fn call(&self, params: P) -> O {
        (self.callback)(params)
    }
    pub fn new(callback: CB) -> Self {
        Self {
            callback: Box::new(callback),
            _data: PhantomData,
        }
    }
}

mod tests {
    use crate::callback::Callback;
    #[test]
    fn test() {
        let callback = Callback::new(example_fn);
        assert!(callback.call("true".to_string()));
        assert!(!callback.call("false".to_string()));
    }
    fn example_fn(paramters: String) -> bool {
        if paramters != "false" {
            return true;
        }
        false
    }
}
