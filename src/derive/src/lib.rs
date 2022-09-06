#![recursion_limit="256"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(PublicKey)]
pub fn public_key_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::interface::PublicKey for #name #ty_generics #where_clause {
            fn get_threshold(&self) -> u32 {
                self.t
            }
        }

        impl #impl_generics crate::interface::Serializable for #name #ty_generics #where_clause {}
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(PrivateKey)]
pub fn private_key_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let public_key_name = syn::Ident::new(&name.to_string().replace("Private", "Public"), name.span());

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::interface::PrivateKey for #name #ty_generics #where_clause {
            type TPubKey = #public_key_name #ty_generics;

            fn get_id(&self) -> u32 {
                self.id
            }

            fn get_public_key(&self) -> Self::TPubKey {
                self.pubkey.clone()
            }

            fn get_threshold(&self) -> u32 {
                self.pubkey.get_threshold()
            }
        }

        impl #impl_generics crate::interface::Serializable for #name #ty_generics #where_clause {}
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Serializable)]
pub fn serializable_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::interface::Serializable for #name #ty_generics #where_clause {}
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(DlShare)]
pub fn dlshare_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics DlShare for #name #ty_generics #where_clause {
            fn get_id(&self) -> u16 { self.id.clone() }

            fn get_group(&self) -> Group { self.data.get_group() }

            fn get_data(&self) -> GroupElement { self.data.clone() }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Ciphertext)]
pub fn ciphertext_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics Ciphertext for #name #ty_generics #where_clause {
            fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
            fn get_label(&self) -> Vec<u8> { self.label.clone() }
        }

        impl #impl_generics crate::interface::Serializable for #name #ty_generics #where_clause {}
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(AsnSequenceTag)]
pub fn derive_asntag_sequence(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics AsnType for #name #ty_generics #where_clause {
            const TAG: rasn::Tag = Tag::SEQUENCE;
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(AsnBitstringTag)]
pub fn derive_asntag_bitstring(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    
    let expanded = quote! {
        impl #impl_generics AsnType for #name #ty_generics #where_clause {
            const TAG: rasn::Tag = Tag::BITSTRING;
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(BigIntegerImpl)]
pub fn derive_big_impl(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut gname = input.ident.clone().to_string();
    gname = gname.replace("BIG", "");
    
    let group_name = syn::Ident::new(&gname, name.span());

    let expanded = quote! {
        impl Encode for #name {
            fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _tag: rasn::Tag) -> Result<(), E::Error> {
                self.to_bytes().encode(encoder)?;
                Ok(())
            }
        }

        impl Decode for #name {
            fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, _tag: rasn::Tag) -> Result<Self, D::Error> {
                let bytes:Vec<u8> = Vec::<u8>::decode(decoder)?.into();

                let val = Self::from_bytes(&bytes);

                match val {
                    BigImpl::#group_name(x) => Ok(x),
                    _ => panic!("Wrong type after deserializing big integer") // TODO: Change this
                }
            }
        }

        impl PartialEq for #name {
            fn eq(&self, other: &Self) -> bool {
                self.equals(&BigImpl::#group_name(other.clone()))
            }
        }

        impl BigInt for #name {
            type DataType = BIG;

            fn new() -> BigImpl {
                BigImpl::#group_name(Self { value: BIG::new() })
            }

            fn new_big(y: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = y {
                    BigImpl::#group_name(Self { value: BIG::new_big(&v.value)})
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn new_copy(y: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = y {
                    BigImpl::#group_name(Self { value:BIG::new_copy(&v.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
                
            }

            fn new_ints(a: &[mcore::arch::Chunk]) -> BigImpl {
                BigImpl::#group_name(Self { value:BIG::new_ints(a) })
            }

            fn new_int(i: isize) -> BigImpl {
                BigImpl::#group_name(Self { value:BIG::new_int(i) })
            }

            fn new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl {
                if let BigImpl::#group_name(v) = q {
                    BigImpl::#group_name(Self { value:BIG::randomnum(&v.value, rng) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn from_bytes(bytes: &[u8]) -> BigImpl {
                BigImpl::#group_name(Self { value:BIG::frombytes(bytes)})
            }

            fn rmod(&mut self, y: &BigImpl) {
                if let BigImpl::#group_name(v) = y {
                    self.value.rmod(&v.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
                if let (BigImpl::#group_name(v), BigImpl::#group_name(w)) = (y, m) {
                    self.value = BIG::mul(&self.value, &v.value).dmod(&w.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }
                
            }

            fn add(&mut self, y: &BigImpl) {
                if let BigImpl::#group_name(v) = y {
                    self.value.add(&v.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn to_bytes(&self) -> Vec<u8> {
                let mut b:Vec<u8> = vec![0; MODBYTES];
                self.value.tobytes(&mut b);
                b
            }

            fn to_string(&self) -> String {
                self.value.tostring()
            }

            fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) {
                if let (BigImpl::#group_name(v), BigImpl::#group_name(w)) = (y, m) {
                    self.value = self.value.powmod(&v.value, &w.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn inv_mod(&mut self, m: &BigImpl) {
                if let BigImpl::#group_name(v) = m {
                    self.value.invmodp(&v.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }   
            }

            fn sub(&mut self, y: &BigImpl) {
                if let BigImpl::#group_name(v) = y {
                    self.value.sub(&v.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }  
            }

            fn imul(&mut self, i: isize) {
                self.value.imul(i);
            }

            fn equals(&self, y: &BigImpl) -> bool {
                if let BigImpl::#group_name(v) = y {
                    BIG::comp(&self.value, &v.value) == 0
                } else {
                    false
                }  
            }
        }

        impl Clone for #name {
            fn clone(&self) -> Self {
                Self{ value: self.value.clone() }
            }
        }
    };

    TokenStream::from(expanded)
}


#[proc_macro_derive(EcPairingGroupImpl)]
pub fn derive_ec_pairing_impl(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident.clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut big_name = input.ident.clone().to_string();
    big_name.push_str("BIG");
    
    let big_impl_name = syn::Ident::new(&big_name, name.span());
    
    let expanded = quote! {
        impl #name {
            pub fn pair(g1: &Self, g2: &Self) -> Result<Self, ThresholdCryptoError> {
                if g1.i != 1 && g2.i != 0 {
                    return Err(ThresholdCryptoError::WrongGroup);
                }
        
                unsafe {
                    let mut rhs = pair::ate(&g1.value.ecp2, &g2.value.ecp);
                    rhs = pair::fexp(&rhs);
                
                    Ok(Self { value: ECPoint {fp12: ManuallyDrop::new(rhs)}, i:2})
                }
            }
        
            pub fn ddh(g1: &Self, g2: &Self, g3:&Self, g4:&Self) -> Result<bool, ThresholdCryptoError> {
                if g1.i != 1 || g2.i != 0 || g3.i != 1 || g4.i != 0 {
                    return Err(ThresholdCryptoError::WrongGroup);
                }
        
                let p1 = Self::pair(g1, g2);
                let p2 = Self::pair(g3, g4);
        
                if p1.is_err() || p2.is_err() {
                    return Err(ThresholdCryptoError::WrongGroup);
                }
                
                Ok(p1.unwrap().equals(&p2.unwrap()))
            }
        
            pub fn new() -> Self {
                Self { value:ECPoint{ecp:ManuallyDrop::new(ECP::generator())}, i:0}
            }
        
            pub fn new_ecp2() -> Self {
                Self { value:ECPoint{ecp2:ManuallyDrop::new(ECP2::generator())}, i:1}
            }
        
            pub fn new_fp12() -> Self {
                Self { value:ECPoint{fp12:ManuallyDrop::new(FP12::new())}, i:2}
            }
            
            pub fn new_pow_big (x: &BigImpl) -> Self {
                if let BigImpl::#name(v) = x {
                    Self { value:ECPoint{ecp:ManuallyDrop::new(ECP::generator().mul(&v.value))}, i:0}
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }
        
            pub fn new_pow_big_ecp2 (x: &BigImpl) -> Self {
                if let BigImpl::#name(v) = x {
                    Self { value:ECPoint{ecp2:ManuallyDrop::new(ECP2::generator().mul(&v.value))}, i:1}
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }
        
            pub fn new_rand(rng: &mut RNG) -> Self {
                Self::new_pow_big(&BigImpl::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
            }
        
            pub fn new_rand_ecp2(rng: &mut RNG) -> Self {
                Self::new_pow_big_ecp2(&BigImpl::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
            }
        
            pub fn new_copy(g: &Self) -> Self {
        
                unsafe {
                    match g.i {
                        0 => Self { value:ECPoint { ecp:g.value.ecp.clone() } , i:g.i},
                        1 => Self { value:ECPoint { ecp2:g.value.ecp2.clone() } , i:g.i},
                        2 => Self { value:ECPoint { fp12:g.value.fp12.clone() } , i:g.i},
                        _ => panic!("invalid i")
                    }
                }
            }
        
            pub fn mul(&mut self, g: &Self) {
                unsafe {
                    match self.i {
                        0 => {(*self.value.ecp).add(&(*g.value.ecp));},
                        1 => {(*self.value.ecp2).add(&(*g.value.ecp2));},
                        2 => {(*self.value.fp12).mul(&(*g.value.fp12));},
                        _ => panic!("invalid i")
                    }
                }
            }
        
            pub fn pow (&mut self, x: &BigImpl) {
                unsafe {
                    if let BigImpl::#name(v) = x {
                        match self.i {
                            0 => self.value.ecp = ManuallyDrop::new(self.value.ecp.mul(&v.value)),
                            1 => self.value.ecp2 = ManuallyDrop::new(self.value.ecp2.mul(&v.value)),
                            2 => self.value.fp12 = ManuallyDrop::new(self.value.fp12.pow(&v.value)),
                            _ => panic!("invalid i")
                        }
                    } else {
                        panic!("Incompatible big integer implementation!");
                    }
                }
            }
        
            pub fn div(&mut self, g: &Self) {
                unsafe {
                    match self.i {
                        0 => {(*self.value.ecp).sub(&g.value.ecp);},
                        1 => {(*self.value.ecp2).sub(&g.value.ecp2);},
                        _ => panic!("invalid i")
                    }
                }
            }
        
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut buf:Vec<u8>;
        
                unsafe {
                    match self.i {
                        0 => {
                            buf = vec![0;2 * MODBYTES + 1];
                            self.value.ecp.tobytes(&mut buf, false)
                        },
                        1 => {
                            buf = vec![0;4 * MODBYTES + 1];
                            self.value.ecp2.tobytes(&mut buf, false)
                        },
                        _ => panic!("invalid i")
                    }
                }
        
                buf
            }
        
            pub fn from_bytes(bytes: &[u8], i:u8) -> Self {
                match i {
                    0 => Self { value:ECPoint{ecp:ManuallyDrop::new(ECP::frombytes(bytes))}, i:0},
                    1 => Self { value:ECPoint{ecp2:ManuallyDrop::new(ECP2::frombytes(bytes))}, i:1},
                    2 => Self { value:ECPoint{fp12:ManuallyDrop::new(FP12::frombytes(bytes))}, i:2},
                    _ => panic!("invalid i")
                }
            }
        
            pub fn equals(&self, g: &Self) -> bool {
                if self.i != g.i {
                    return false;
                }
        
                unsafe {
                    match self.i {
                        0 => self.value.ecp.equals(&g.value.ecp),
                        1 => self.value.ecp2.equals(&g.value.ecp2),
                        2 => self.value.fp12.equals(&g.value.fp12),
                        _ => panic!("invalid i")
                    }
                }
            }
        
            pub fn get_order() -> BigImpl {
                #big_impl_name::new_ints(&rom::CURVE_ORDER)
            }
        
            pub fn nbytes() -> usize {
                2*MODBYTES 
            }
        
            pub fn to_string(&self) -> String {
                unsafe {
                    match self.i {
                        0 => self.value.ecp.tostring(),
                        1 => self.value.ecp2.tostring(),
                        2 => self.value.fp12.tostring(),
                        _ => panic!("invalid i")
                    }
                }
            }
        
            pub fn get_name() -> String {
                "#name".to_string()
            }
        }

        impl PartialEq for #name {
            fn eq(&self, other: &Self) -> bool {
                if self.i != other.i {
                    return false
                }
                unsafe {
                    match self.i {
                        0 => return self.value.ecp.equals(&other.value.ecp),
                        1 => return self.value.ecp2.equals(&other.value.ecp2),
                        2 => return self.value.fp12.equals(&other.value.fp12),
                        _ => panic!("invalid i value")
                    }
                }
            }
        }
        
        impl Clone for #name {
            fn clone(&self) -> Self {
                unsafe {
                    match self.i {
                        0 => Self{ value: ECPoint{ ecp:self.value.ecp.clone() }, i:0 },
                        1 => Self{ value: ECPoint{ ecp2:self.value.ecp2.clone() }, i:1 },
                        2 => Self{ value: ECPoint{ fp12:self.value.fp12.clone() }, i:2 },
                        _ => panic!("invalid i value")
                    }
                }
                
            }
        }
    };

    TokenStream::from(expanded)
}


#[proc_macro_derive(EcGroupImpl)]
pub fn derive_ec_impl(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident.clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut big_name = input.ident.clone().to_string();
    big_name.push_str("BIG");
    
    let big_impl_name = syn::Ident::new(&big_name, name.span());
    
    let expanded = quote! {
        impl #name {
            pub fn new() -> Self {
                Self { value:ECP::generator() }
            }
        
            
            pub fn new_pow_big (x: &BigImpl) -> Self {
                if let BigImpl::#name(v) = x {
                    Self { value:ECP::generator().mul(&v.value) }
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }
        
            pub fn new_rand(rng: &mut RNG) -> Self {
                Self::new_pow_big(&BigImpl::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
            }
        
            pub fn new_copy(g: &Self) -> Self {
                Self { value:g.value.clone() }
            }
        
            pub fn mul(&mut self, g: &Self) {
                self.value.add(&g.value);
            }
        
            pub fn pow (&mut self, x: &BigImpl) {
                if let BigImpl::#name(v) = x {
                    self.value = self.value.mul(&v.value);
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }
        
            pub fn div(&mut self, g: &Self) {
                self.value.sub(&g.value);
            }
        
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut buf:Vec<u8>;
                buf = vec![0;2 * MODBYTES + 1];
                self.value.tobytes(&mut buf, false);
                buf
            }
        
            pub fn from_bytes(bytes: &[u8]) -> Self {
                Self { value:ECP::frombytes(bytes) }
            }
        
            pub fn equals(&self, g: &Self) -> bool {
                self.value.equals(&g.value)
            }
        
            pub fn get_order() -> BigImpl {
                #big_impl_name::new_ints(&rom::CURVE_ORDER)
            }
        
            pub fn nbytes() -> usize {
                2*MODBYTES 
            }
        
            pub fn to_string(&self) -> String {
                self.value.tostring()
            }
        
            pub fn get_name() -> String {
                "#name".to_string()
            }
        }

        impl PartialEq for #name {
            fn eq(&self, other: &Self) -> bool {
                return self.value.equals(&other.value);
           
            }
        }
        
        impl Clone for #name {
            fn clone(&self) -> Self {
                Self{ value:self.value.clone() }
            }
        }
    };

    TokenStream::from(expanded)
}