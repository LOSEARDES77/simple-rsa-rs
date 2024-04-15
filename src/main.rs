use num_bigint::{BigInt, ToBigInt};



#[derive(Clone)]
struct Rsa {
    n: BigInt,
    e: BigInt,
    d: BigInt,
    pub public_key: (BigInt, BigInt)
}

impl Rsa{
    

    fn euclides(a: BigInt, b: BigInt) -> BigInt{
        if b == 0.to_bigint().unwrap() { a } else { Rsa::euclides(b.clone(), a % b) }
    }
    
    fn mod_inverse(e: BigInt, m: BigInt) -> Option<BigInt> {
        let mut m = m;
        let mut e= e;
        let m0 = m.clone();
        let mut t;
        let mut q;
        let mut x0 = 0.to_bigint().unwrap();
        let mut x1 = 1.to_bigint().unwrap();
        if m == 1.to_bigint().unwrap()  {
            return Some(0.to_bigint().unwrap());
        }
        while e > 1.to_bigint().unwrap() {
            q = e.clone() / m.clone();
            t = m.clone();
            m = e % m.clone();
            e = t.clone();
            t = x0.clone();
            x0 = x1 - q * x0;
            x1 = t;
        }
        if x1 < 0.to_bigint().unwrap() {
            x1 += m0;
        }
        Some(x1)
    }


    fn find_coprime(n: BigInt) -> BigInt{
        loop{
            let random_num: BigInt = (rand::random::<u128>() % (n.clone() - 1)) + 1;
            if random_num != 1.to_bigint().unwrap() && Rsa::euclides(n.clone(), random_num.clone()) == 1.to_bigint().unwrap() {
                return random_num;
            }
        }
    }

    pub fn new(p: u128, q: u128) -> Rsa{
        let n = q.to_bigint().unwrap() * p.to_bigint().unwrap();
        let e = Rsa::find_coprime((p-1).to_bigint().unwrap() * (q-1).to_bigint().unwrap());

        let public_key = (n.clone(), e.clone());

        let d = Rsa::mod_inverse(e.to_bigint().unwrap(), (p-1).to_bigint().unwrap() * (q-1).to_bigint().unwrap() ).unwrap();

        Rsa{ n, e, d, public_key}
    }
    #[allow(dead_code)]
    pub fn encrypt(self, m: u128) -> BigInt {
        let m = m.to_bigint().unwrap();
        let e = self.e.to_bigint().unwrap();
        let n = self.n.to_bigint().unwrap();
        let res = m.modpow(&e, &n);
        res
    }
    #[allow(dead_code)]
    pub fn str_encrypt(self, m: &str) -> Vec<BigInt> {
        m.chars().map(|c| <Rsa as Clone>::clone(&self).encrypt(c as u128)).collect()
    }
    
    #[allow(dead_code)]
    pub fn decrypt(self, m: BigInt) -> u128{
        let m = m.to_bigint().unwrap();
        let d = self.d.to_bigint().unwrap();
        let n = self.n.to_bigint().unwrap();
        let res = m.modpow(&d, &n);
        res.try_into().unwrap()
    }
    #[allow(dead_code)]
    pub fn str_decrypt(self, m: Vec<BigInt>) -> String {
        m.iter().map(|c| <Rsa as Clone>::clone(&self).decrypt(c.to_bigint().unwrap()) as u8 as char).collect()
    }
}

fn main(){
    let rsa = Rsa::new(222333355557757777577, 91629612429162961243);

    println!("Public Key: {:?}", rsa.public_key);

    let message = 100;
    let encrypted = rsa.clone().encrypt(message);

    println!("Encrypted: {}", encrypted);
    
    let original = rsa.decrypt(encrypted);

    println!("Original: {}", original);

    assert_eq!(message, original);

}


mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_rsa(){
        for _ in 0..100 {
            
            let rsa = Rsa::new(1000000007, 1000000009);
    
            let message = rand::random::<u128>() % 10000;
            let encrypted = rsa.clone().encrypt(message);
            let original = rsa.decrypt(encrypted);
    
            assert_eq!(message, original);
        }
    }

    #[test]
    fn test_euclides(){

        assert_eq!(Rsa::euclides(3.to_bigint().unwrap(), 10.to_bigint().unwrap()), 1.to_bigint().unwrap());
        assert_eq!(Rsa::euclides(5.to_bigint().unwrap(), 10.to_bigint().unwrap()), 5.to_bigint().unwrap());
        assert_eq!(Rsa::euclides(2.to_bigint().unwrap(), 10.to_bigint().unwrap()), 2.to_bigint().unwrap());
    }

    #[test]
    fn test_mod_inverse(){
        assert_eq!(Rsa::mod_inverse(3.to_bigint().unwrap(), 11.to_bigint().unwrap()), Some(4.to_bigint().unwrap()));
        assert_eq!(Rsa::mod_inverse(5.to_bigint().unwrap(), 11.to_bigint().unwrap()), Some(9.to_bigint().unwrap()));
        assert_eq!(Rsa::mod_inverse(7.to_bigint().unwrap(), 11.to_bigint().unwrap()), Some(8.to_bigint().unwrap()));
        
    }

    #[test]
    fn test_find_coprime(){
        let n = 1000000007.to_bigint().unwrap() * 1000000009.to_bigint().unwrap();
        let coprime = Rsa::find_coprime(n.clone());
        assert_eq!(Rsa::euclides(n, coprime), 1.to_bigint().unwrap());
    }

    #[test]
    fn test_strings(){
        let rsa = Rsa::new(222333355557757777577, 91629612429162961243);

        let message = "Hello, World!";

        let encrypted = rsa.clone().str_encrypt(message);

        let encrypted_str = encrypted.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(" ");
        println!("Encrypted: {}", encrypted_str);

        let original = rsa.str_decrypt(encrypted);

        println!("Original: {}", original);

        assert_eq!(message, original);
    }
}


