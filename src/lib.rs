pub mod descriptors;
pub mod formats;
pub mod json;
pub mod xpub;

pub type Format = formats::Format;

pub fn parse_from_str(string: &str) -> Result<formats::Format, formats::Error> {
    formats::Format::try_new_from_str(string)
}
