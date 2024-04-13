use num_bigint::ToBigInt;




#[derive(Clone, Copy)]
struct Rsa {
    n: u128,
    e: u128,
    d: u128,
    pub public_key: (u128, u128)
}

impl Rsa{
    

    fn euclides(a: u128, b: u128) -> u128{
        if b == 0 { a } else { Rsa::euclides(b, a % b) }
    }
    
    fn mod_inverse(e: u128, m: u128) -> Option<u128> {
        let mut m: i128 = m.try_into().unwrap();
        let mut e: i128 = e.try_into().unwrap();
        let m0 = m;
        let mut t;
        let mut q;
        let mut x0 = 0;
        let mut x1 = 1;
        if m == 1 {
            return Some(0);
        }
        while e > 1 {
            q = e / m;
            t = m;
            m = e % m;
            e = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if x1 < 0 {
            x1 += m0;
        }
        Some(x1.try_into().unwrap())
    }


    fn find_coprime(n: u128) -> u128{
        loop{
            let random_num = (rand::random::<u128>() % (n - 1)) + 1;
            if random_num != 1 && Rsa::euclides(n, random_num) == 1 {
                return random_num;
            }
        }
    }

    pub fn new(p: u128, q: u128) -> Rsa{
        let n = q*p;
        let e = Rsa::find_coprime((p-1) * (q-1));

        let public_key = (n, e);

        let d = Rsa::mod_inverse(e, (p-1)*(q-1)).unwrap();

        Rsa{ n, e, d, public_key}
    }
    #[allow(dead_code)]
    pub fn encrypt(self, m: u128) -> u128 {
        let m = m.to_bigint().unwrap();
        let e = self.e.to_bigint().unwrap();
        let n = self.n.to_bigint().unwrap();
        let res = m.modpow(&e, &n);
        res.try_into().unwrap()
    }
    #[allow(dead_code)]
    pub fn str_encrypt(self, m: &str) -> Vec<u128> {
        m.chars().map(|c| self.encrypt(c as u128)).collect()
    }
    
    #[allow(dead_code)]
    pub fn decrypt(self, m: u128) -> u128{
        let m = m.to_bigint().unwrap();
        let d = self.d.to_bigint().unwrap();
        let n = self.n.to_bigint().unwrap();
        let res = m.modpow(&d, &n);
        res.try_into().unwrap()
    }
    #[allow(dead_code)]
    pub fn str_decrypt(self, m: Vec<u128>) -> String {
        m.iter().map(|c| self.decrypt(*c) as u8 as char).collect()
    }
}

fn main(){
    let rsa = Rsa::new(1000000007, 1000000009);

    println!("Public Key: {:?}", rsa.public_key);

    let message = 100;
    let encrypted = rsa.encrypt(message);

    println!("Encrypted: {}", encrypted);
    
    let original = rsa.decrypt(encrypted);

    println!("Original: {}", original);

    assert_eq!(message, original);

}


mod tests {
    #[allow(unused_imports)]
    use crate::Rsa;

    #[test]
    fn test_rsa(){
        for _ in 0..100 {
            
            let rsa = Rsa::new(1000000007, 1000000009);
    
            let message = rand::random::<u128>() % 10000;
            let encrypted = rsa.encrypt(message);
            let original = rsa.decrypt(encrypted);
    
            assert_eq!(message, original);
        }
    }

    #[test]
    fn test_euclides(){
        assert_eq!(Rsa::euclides(10, 5), 5);
        assert_eq!(Rsa::euclides(10, 3), 1);
        assert_eq!(Rsa::euclides(10, 2), 2);
    }

    #[test]
    fn test_mod_inverse(){
        assert_eq!(Rsa::mod_inverse(3, 11), Some(4));
        assert_eq!(Rsa::mod_inverse(5, 11), Some(9));
        assert_eq!(Rsa::mod_inverse(7, 11), Some(8));
    }

    #[test]
    fn test_find_coprime(){
        let n = 1000000007 * 1000000009;
        let coprime = Rsa::find_coprime(n);
        assert_eq!(Rsa::euclides(n, coprime), 1);
    }

    #[test]
    fn test_strings(){
        let rsa = Rsa::new(1000000007, 1000000009);

        let message = "Hello, World!";

        let encrypted = rsa.str_encrypt(message);

        let encrypted_str = encrypted.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(" ");
        println!("Encrypted: {}", encrypted_str);

        let original = rsa.str_decrypt(encrypted);

        println!("Original: {}", original);

        assert_eq!(message, original);
    }
}


