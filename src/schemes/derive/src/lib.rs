#![recursion_limit = "256"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(PublicKey)]
pub fn public_key_derive(input: TokenStream) -> TokenStream {
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
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(PrivateKey)]
pub fn private_key_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let public_key_name =
        syn::Ident::new(&name.to_string().replace("Private", "Public"), name.span());

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
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(DlShare)]
pub fn dlshare_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics DlShare for #name #ty_generics #where_clause {
            fn get_id(&self) -> u16 { self.id }

            fn get_group(&self) -> &Group { self.data.get_group() }

            fn get_data(&self) -> &GroupElement { &self.data }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Ciphertext)]
pub fn ciphertext_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics Ciphertext for #name #ty_generics #where_clause {
            fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
            fn get_label(&self) -> Vec<u8> { self.label.clone() }
        }

    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(AsnSequenceTag)]
pub fn derive_asntag_sequence(input: TokenStream) -> TokenStream {
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
pub fn derive_asntag_bitstring(input: TokenStream) -> TokenStream {
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
pub fn derive_big_impl(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let mut gname = input.ident.clone().to_string();
    gname = gname.replace("BIG", "");

    let group_name = syn::Ident::new(&gname, name.span());

    let expanded = quote! {
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

            fn rmod(&self, y: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.rmod(&v.value);
                    BigImpl::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn mul_mod(&self, y: &BigImpl, m: &BigImpl) -> BigImpl {
                if let (BigImpl::#group_name(v), BigImpl::#group_name(w)) = (y, m) {
                    BigImpl::#group_name(Self { value:BIG::mul(&self.value, &v.value).dmod(&w.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }

            }

            fn add(&self, y: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.add(&v.value);
                    BigImpl::#group_name(x)
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

            fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) -> BigImpl {
                if let (BigImpl::#group_name(v), BigImpl::#group_name(w)) = (y, m) {
                    BigImpl::#group_name(Self { value:self.value.powmod(&v.value, &w.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn inv_mod(&self, m: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = m {
                    let mut x = self.clone();
                    x.value.invmodp(&v.value);
                    BigImpl::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn sub(&self, y: &BigImpl) -> BigImpl {
                if let BigImpl::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.sub(&v.value);
                    BigImpl::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn imul(&self, i: isize) -> BigImpl {
                let mut x = self.clone();
                x.value.imul(i);
                BigImpl::#group_name(x)
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
pub fn derive_ec_pairing_impl(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident.clone();
    let lname = input.ident.clone().to_string().to_lowercase();

    let mut big_name = input.ident.clone().to_string();
    big_name.push_str("BIG");

    let big_impl_name = syn::Ident::new(&big_name, name.span());
    let name_lower = syn::Ident::new(&lname, name.span());

    let expanded = quote! {
        use crate::group::GroupData;

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

            pub fn identity() -> Self {
                unsafe {
                    let mut x = Self::new();
                    (*x.value.ecp).inf();
                    x
                }
            }

            pub fn new() -> Self {
                Self { value: ECPoint{ecp:ManuallyDrop::new(ECP::generator())}, i:0}
            }

            pub fn new_ecp2() -> Self {
                Self { value: ECPoint{ecp2:ManuallyDrop::new(ECP2::generator())}, i:1}
            }

            pub fn new_fp12() -> Self {
                Self { value: ECPoint{fp12:ManuallyDrop::new(FP12::new())}, i:2}
            }

            pub fn new_from_ecp(point: ECP) -> Self {
                Self { value: ECPoint{ecp:ManuallyDrop::new(point)}, i:0 }
            }

            pub fn new_from_ecp2(point: ECP2) -> Self {
                Self { value: ECPoint{ecp2:ManuallyDrop::new(point)}, i:1 }
            }

            pub fn new_from_fp12(point: FP12) -> Self {
                Self { value: ECPoint{fp12:ManuallyDrop::new(point)}, i:2 }
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

            pub fn mul(&self, g: &Self) -> GroupElement {
                unsafe {
                    let result;
                    match self.i {
                        0 => {
                            let mut val = (*self.value.ecp).clone();
                            val.add(&(*g.value.ecp));
                            result = Self { value:ECPoint{ecp:ManuallyDrop::new(val)}, i:0};
                        },
                        1 => {
                            let mut val = (*self.value.ecp2).clone();
                            val.add(&(*g.value.ecp2));
                            result =  Self { value:ECPoint{ecp2:ManuallyDrop::new(val)}, i:1};
                        },
                        2 => {
                            let mut val = (*self.value.fp12).clone();
                            val.mul(&(*g.value.fp12));
                            result = Self { value:ECPoint{fp12:ManuallyDrop::new(val)}, i:2};
                        },
                        _ => panic!("invalid i")
                    }

                    GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new(result)})
                }
            }

            pub fn pow (&self, x: &BigImpl) -> GroupElement {
                unsafe {
                    let result;
                    if let BigImpl::#name(v) = x {
                        match self.i {
                            0 => result = Self { value: ECPoint{ ecp:ManuallyDrop::new(self.value.ecp.mul(&v.value)) }, i:0},
                            1 => result = Self { value: ECPoint{ ecp2:ManuallyDrop::new(self.value.ecp2.mul(&v.value)) }, i:1},
                            2 => result = Self { value: ECPoint{ fp12:ManuallyDrop::new(self.value.fp12.pow(&v.value)) }, i:2},
                            _ => panic!("invalid i")
                        }
                    } else {
                        panic!("Incompatible big integer implementation!");
                    }

                    GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new(result)})
                }
            }

            pub fn div(&self, g: &Self) -> GroupElement {
                unsafe {
                    let result;
                    match self.i {
                        0 => {
                            let mut val = (*self.value.ecp).clone();
                            val.sub(&g.value.ecp);
                            result = Self { value: ECPoint { ecp:ManuallyDrop::new(val) }, i:0};
                        },
                        1 => {
                            let mut val = (*self.value.ecp2).clone();
                            val.sub(&g.value.ecp2);
                            result = Self { value: ECPoint { ecp2:ManuallyDrop::new(val) }, i:1};
                        },
                        _ => panic!("invalid i")
                    }

                    GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new(result)})
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
pub fn derive_ec_impl(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident.clone();

    let lname = input.ident.clone().to_string().to_lowercase();

    let mut big_name = input.ident.clone().to_string();
    big_name.push_str("BIG");

    let big_impl_name = syn::Ident::new(&big_name, name.span());
    let name_lower = syn::Ident::new(&lname, name.span());

    let expanded = quote! {
        use crate::group::GroupData;
        use std::mem::ManuallyDrop;

        impl #name {
            pub fn new() -> Self {
                Self { value:ECP::generator() }
            }

            pub fn identity() -> Self {
                let mut x = Self::new();
                x.value.inf();
                x
            }

            pub fn new_pow_big (x: &BigImpl) -> Self {
                if let BigImpl::#name(v) = x {
                    return Self { value:ECP::generator().mul(&v.value) };
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

            pub fn mul(&self, g: &Self) -> GroupElement {
                let mut v = self.value.clone();
                v.add(&g.value);
                GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new(Self { value:v })})
            }

            pub fn pow (&self, x: &BigImpl) -> GroupElement {
                if let BigImpl::#name(v) = x {
                    GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new( Self { value: self.value.mul(&v.value) }) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            pub fn div(&self, g: &Self) -> GroupElement {
                let mut v = self.value.clone();
                v.sub(&g.value);
                GroupElement::create(Group::#name, GroupData{#name_lower:ManuallyDrop::new( Self { value: v } ) })
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
