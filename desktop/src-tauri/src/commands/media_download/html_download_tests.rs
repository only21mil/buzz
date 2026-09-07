use super::*;

#[test]
fn html_is_downloadable_but_never_an_image() {
    for bytes in [
        b"<!DOCTYPE html><html><script>alert(1)</script></html>".as_slice(),
        b"  \n<!DOCTYPE html><html>whitespace</html>",
        b"\xef\xbb\xbf<html>BOM</html>",
        b"<!-- comment --><html>comment</html>",
        b"<p>fragment</p>",
        b"",
    ] {
        assert!(detect_and_validate_mime(bytes).is_ok());
        assert!(validate_image_bytes(bytes).is_err());
    }
    assert!(validate_image_bytes(&[0xff, 0xd8, 0xff, 0xe0]).is_ok());
    assert!(detect_and_validate_mime(b"MZ\x90\x00").is_err());
}
