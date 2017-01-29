use std::io::Read;
use std::fs::{File, remove_file};

use data_encoding::base64;
use qrcode::QrCode;
use image::GrayImage;
use libreauth::oath::TOTPBuilder;



pub fn verify(key: String, code: String) -> bool {
    let totp = TOTPBuilder::new()
                .base32_key(&key)
                .tolerance(1) // allows for 30s drift
                .finalize()
                .unwrap();

    totp.is_valid(&code)
}

// Need a good way of serving a dynamically-generated image
// Don't wanna save the file to a resolvable path
//
// Disgusting workaround for the time being:
//     - ImageBuffer::save() to PNG temp file
//     - Read the file into a Vec<u8>
//     - Encode the buffer into a data URI
#[get("/qr/<key>/<user>")]
pub fn qr_image_uri(key: String, user: String) -> String {
    let path = "/tmp/".to_string() + &key + ".png";

    {
        // TODO: Percent-encoding
        let payload = "otpauth://totp/RocketDemo:".to_string() + &user + "?secret=" + &key;

        let qr = QrCode::new(payload.as_bytes()).unwrap();
        let image: GrayImage = qr.render().to_image();

        image.save(&path).unwrap();
    }

    let mut buffer = Vec::new();
    {
        let mut qr_file = File::open(&path).unwrap();
        let _ = qr_file.read_to_end(&mut buffer);
    }
    let _ = remove_file(&path);

    "data:image/png;base64,".to_string() + &base64::encode(&buffer)
}
