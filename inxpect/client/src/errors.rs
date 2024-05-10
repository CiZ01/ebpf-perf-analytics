use std::{error::Error, fmt};

#[derive(Debug)]
pub struct InxpectServerErr {
    code: i32,
    message: &'static str,
}

impl Error for InxpectServerErr {}

// TODO: InxpectServerErr not implement Error
impl fmt::Display for InxpectServerErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl InxpectServerErr {
    fn new(code: i32, message: &'static str) -> InxpectServerErr {
        InxpectServerErr { code, message }
    }
    pub fn get_err(code: i32) -> InxpectServerErr {
        match code {
            0 => NONE,
            1 => UNKNOWN_CMD,
            2 => INVALID,
            3 => INTERNAL,
            _ => UNKNOWN,
        }
    }
}

const UNKNOWN: InxpectServerErr = InxpectServerErr {
    code: -1,
    message: "Unknown error",
};

const NONE: InxpectServerErr = InxpectServerErr {
    code: 0,
    message: "Success!",
};

const UNKNOWN_CMD: InxpectServerErr = InxpectServerErr {
    code: 1,
    message: "Bad request",
};

const INVALID: InxpectServerErr = InxpectServerErr {
    code: 2,
    message: "Arguments not valid",
};

const INTERNAL: InxpectServerErr = InxpectServerErr {
    code: 3,
    message: "Internal Server Error",
};
