//! The unit of text a detector inspects, plus its direction of travel.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Input,
    Output,
}

/// A borrowed view of the text under inspection. Zero-copy by design.
pub struct Context<'a> {
    pub text: &'a str,
    pub direction: Direction,
}

impl<'a> Context<'a> {
    pub fn input(text: &'a str) -> Self {
        Self {
            text,
            direction: Direction::Input,
        }
    }

    pub fn output(text: &'a str) -> Self {
        Self {
            text,
            direction: Direction::Output,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_direction() {
        assert_eq!(Context::input("hi").direction, Direction::Input);
        assert_eq!(Context::output("hi").direction, Direction::Output);
    }
}
