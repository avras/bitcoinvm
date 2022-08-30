pub fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

pub fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

pub fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

pub fn f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

pub fn f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

#[cfg(test)]
mod tests {
    use super::{f1, f2, f3, f4, f5};
    use rand::Rng;


    #[test]
    fn test_f1 () {
        assert_eq!(f1(0, 0, 0), 0);
        assert_eq!(f1(0xFF, 0xFF, 0xFF), 0xFF);
        assert_eq!(f1(0xAB, 0xBC, 0xCD), 0xDA);
    }

    #[test]
    fn test_f2 () {
        assert_eq!(f2(0, 0, 0), 0);
        assert_eq!(f2(0xFF, 0xFF, 0xFF), 0xFF);
        
        let mut rng = rand::thread_rng();
        let y: u32 = rng.gen();
        let z: u32 = rng.gen();
        assert_eq!(f2(0xFFFF_FFFF, y, z), y);
        assert_eq!(f2(0, y, z), z);
    }

    #[test]
    fn test_f3 () {
        assert_eq!(f3(0, 0, 0), 0xFFFF_FFFF);
        assert_eq!(f3(0xFF, 0xFF, 0xFF), 0xFFFF_FF00);
        assert_eq!(f3(0xAB, 0xBC, 0xCD), 0xFFFF_FF26);
    }

    #[test]
    fn test_f4 () {
        assert_eq!(f4(0, 0, 0), 0);
        assert_eq!(f4(0xFF, 0xFF, 0xFF), 0xFF);
        
        let mut rng = rand::thread_rng();
        let x: u32 = rng.gen();
        let y: u32 = rng.gen();
        assert_eq!(f4(x, y, 0xFFFF_FFFF), x);
        assert_eq!(f4(x, y, 0), y);
    }

    #[test]
    fn test_f5 () {
        assert_eq!(f5(0, 0, 0), 0xFFFF_FFFF);
        assert_eq!(f5(0xFF, 0xFF, 0xFF), 0xFFFF_FF00);
        assert_eq!(f5(0xAB, 0xBC, 0xCD), 0xFFFF_FF15);
    }
}