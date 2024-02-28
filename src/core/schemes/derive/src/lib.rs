#![recursion_limit = "256"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use proc_macro::Ident;
use quote::{quote, ToTokens};
use syn::{DeriveInput, FieldsNamed};

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
                self.equals(&SizedBigInt::#group_name(other.clone()))
            }
        }

        impl FixedSizeInt for #name {
            type DataType = BIG;

            fn new() -> SizedBigInt {
                SizedBigInt::#group_name(Self { value: BIG::new() })
            }

            fn new_copy(y: &SizedBigInt) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = y {
                    SizedBigInt::#group_name(Self { value:BIG::new_copy(&v.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }

            }

            fn new_ints(a: &[mcore::arch::Chunk]) -> SizedBigInt {
                SizedBigInt::#group_name(Self { value:BIG::new_ints(a) })
            }

            fn new_int(i: isize) -> SizedBigInt {
                SizedBigInt::#group_name(Self { value:BIG::new_int(i) })
            }

            fn new_rand(q: &SizedBigInt, rng: &mut RNG) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = q {
                    SizedBigInt::#group_name(Self { value:BIG::randomnum(&v.value, rng) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn from_bytes(bytes: &[u8]) -> SizedBigInt {
                SizedBigInt::#group_name(Self { value:BIG::frombytes(bytes)})
            }

            fn rmod(&self, y: &SizedBigInt) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.rmod(&v.value);
                    SizedBigInt::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn mul_mod(&self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt {
                if let (SizedBigInt::#group_name(v), SizedBigInt::#group_name(w)) = (y, m) {
                    SizedBigInt::#group_name(Self { value:BIG::mul(&self.value, &v.value).dmod(&w.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }

            }

            fn add(&self, y: &SizedBigInt) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.add(&v.value);
                    SizedBigInt::#group_name(x)
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

            fn pow_mod(&mut self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt {
                if let (SizedBigInt::#group_name(v), SizedBigInt::#group_name(w)) = (y, m) {
                    SizedBigInt::#group_name(Self { value:self.value.powmod(&v.value, &w.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn inv_mod(&self, m: &SizedBigInt) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = m {
                    let mut x = self.clone();
                    x.value.invmodp(&v.value);
                    SizedBigInt::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn sub(&self, y: &SizedBigInt) -> SizedBigInt {
                if let SizedBigInt::#group_name(v) = y {
                    let mut x = self.clone();
                    x.value.sub(&v.value);
                    SizedBigInt::#group_name(x)
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            fn imul(&self, i: isize) -> SizedBigInt {
                let mut x = self.clone();
                x.value.imul(i);
                SizedBigInt::#group_name(x)
            }

            fn equals(&self, y: &SizedBigInt) -> bool {
                if let SizedBigInt::#group_name(v) = y {
                    BIG::comp(&self.value, &v.value) == 0
                } else {
                    false
                }
            }

            fn cmp(&self, y: &SizedBigInt) -> isize {
                if let SizedBigInt::#group_name(v) = y {
                    BIG::comp(&self.value, &v.value)
                } else {
                    panic!("Incompatible big integer implementation!");
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
        impl #name {
            pub fn pair(g1: &Self, g2: &Self) -> Result<Self, SchemeError> {
                if g1.i != 1 || g2.i != 0 {
                    return Err(SchemeError::WrongGroup);
                }

                unsafe {
                    let mut rhs = pair::ate(&g1.value.ecp2, &g2.value.ecp);
                    rhs = pair::fexp(&rhs);

                    Ok(Self { value: ECPoint {fp12: ManuallyDrop::new(rhs)}, i:2})
                }
            }

            pub fn ddh(g1: &Self, g2: &Self, g3:&Self, g4:&Self) -> Result<bool, SchemeError> {
                if g1.i != 1 || g2.i != 0 || g3.i != 1 || g4.i != 0 {
                    return Err(SchemeError::WrongGroup);
                }

                let p1 = Self::pair(g1, g2);
                let p2 = Self::pair(g3, g4);

                if p1.is_err() || p2.is_err() {
                    return Err(SchemeError::WrongGroup);
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

            pub fn new_pow_big (x: &SizedBigInt) -> Self {
                if let SizedBigInt::#name(v) = x {
                    Self { value:ECPoint{ecp:ManuallyDrop::new(ECP::generator().mul(&v.value))}, i:0}
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            pub fn new_pow_big_ecp2 (x: &SizedBigInt) -> Self {
                if let SizedBigInt::#name(v) = x {
                    Self { value:ECPoint{ecp2:ManuallyDrop::new(ECP2::generator().mul(&v.value))}, i:1}
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            pub fn new_rand(rng: &mut RNG) -> Self {
                Self::new_pow_big(&SizedBigInt::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
            }

            pub fn new_rand_ecp2(rng: &mut RNG) -> Self {
                Self::new_pow_big_ecp2(&SizedBigInt::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
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

                    GroupElement::#name(result)
                }
            }

            pub fn pow (&self, x: &SizedBigInt) -> GroupElement {
                unsafe {
                    let result;
                    if let SizedBigInt::#name(v) = x {
                        match self.i {
                            0 => result = Self { value: ECPoint{ ecp:ManuallyDrop::new(self.value.ecp.mul(&v.value)) }, i:0},
                            1 => result = Self { value: ECPoint{ ecp2:ManuallyDrop::new(self.value.ecp2.mul(&v.value)) }, i:1},
                            2 => result = Self { value: ECPoint{ fp12:ManuallyDrop::new(self.value.fp12.pow(&v.value)) }, i:2},
                            _ => panic!("invalid i")
                        }
                    } else {
                        panic!("Incompatible big integer implementation!");
                    }

                    GroupElement::#name(result)
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

                    GroupElement::#name(result)
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

            // TODO: convert to reference
            pub fn get_order() -> SizedBigInt {
                #big_impl_name::new_ints(&rom::CURVE_ORDER)
            }

            // TODO: precompute
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

            pub fn new_pow_big (x: &SizedBigInt) -> Self {
                if let SizedBigInt::#name(v) = x {
                    return Self { value:ECP::generator().mul(&v.value) };
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            pub fn new_rand(rng: &mut RNG) -> Self {
                Self::new_pow_big(&SizedBigInt::#name(#big_impl_name { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
            }

            pub fn new_copy(g: &Self) -> Self {
                Self { value:g.value.clone() }
            }

            pub fn mul(&self, g: &Self) -> GroupElement {
                let mut v = self.value.clone();
                v.add(&g.value);
                GroupElement::#name(Self { value:v })
            }

            pub fn pow (&self, x: &SizedBigInt) -> GroupElement {
                if let SizedBigInt::#name(v) = x {
                    GroupElement::#name(Self { value: self.value.mul(&v.value) })
                } else {
                    panic!("Incompatible big integer implementation!");
                }
            }

            pub fn div(&self, g: &Self) -> GroupElement {
                let mut v = self.value.clone();
                v.sub(&g.value);
                GroupElement::#name(Self { value:v })
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

            pub fn get_order() -> SizedBigInt {
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

#[proc_macro_derive(GroupWrapper)]
pub fn derive_group_data(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident.clone();

    let mut fields: Vec<String> = Vec::new();

    match input.data.clone() {
        syn::Data::Union(s) => {
            fields = s
                .fields
                .named
                .iter()
                .map(|f| f.ident.clone().unwrap().to_string())
                .collect();
        }
        _ => {}
    };

    // let expanded = quote! {
    //     impl PartialEq for #name {
    //         fn eq(&self, other: &Self) -> bool {
    //             if mem::discriminant(self) != mem::discriminant(other) {
    //                 return false;
    //             }

    //             match self {
    //                 Self::Bls12381(x) => {
    //                     if let Self::(#fields[0])(y) = other {
    //                         return x.eq(y);
    //                     }
    //                 }
    //                 _ => {
    //                     return false;
    //                 }
    //             }
    //         }
    //     }
    // };
    TokenStream::from(quote! {})
    //TokenStream::from(expanded)
}

/*
#[proc_macro_derive(GroupWrapper)]
pub fn derive_group_wrapper(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident.clone();

    //let attr = input.data.

    //println!("{}", a_token);

    //let item = syn::parse(input).expect("failed to parse input");

    /*let lname = input.ident.clone().to_string().to_lowercase();

    let mut big_name = input.ident.clone().to_string();
    big_name.push_str("BIG");

    let big_impl_name = syn::Ident::new(&big_name, name.span());
    let name_lower = syn::Ident::new(&lname, name.span());*/

    let description = match input.data.clone() {
        syn::Data::Struct(s) => match s.fields {
            syn::Fields::Named(FieldsNamed { named, .. }) => {
                let mut fields = named.iter();
                fields.next();
                let data = fields.next().unwrap();

                //let s: TokenStream = data.into_token_stream().into();

                //let i = syn::parse_macro_input!(s as DeriveInput);

                /*let variants = match i.data.clone() {
                    syn::Data::Enum(enum_item) => enum_item.variants.into_iter().map(|v| v.ident),
                    _ => panic!("AllVariants only works on enums"),
                };*/

                //format!("{}", quote! {#(#variants), *})

                format!("{}", data.ident.as_ref().unwrap().to_string())
            }
            _ => String::from(""),
        },
        _ => String::from(""),
    };

    /*let variants = match input.data {
        syn::Data::Enum(enum_item) => enum_item.variants.into_iter().map(|v| v.ident),
        _ => panic!("AllVariants only works on enums"),
    };*/

    let expanded = quote! {
        impl #name {
            pub fn describe() {
                println!("{} is {}.", stringify!(#name), #description);
            }
        }
        //use std::mem::ManuallyDrop;

        /*impl PartialEq for #name {
            fn eq(&self, other: &Self) -> bool {
                if self.group != other.group {
                    return false;
                }
                unsafe {
                    match self.group {
                        Group::Bls12381 => (*self.data.bls12381).eq(&other.data.bls12381),
                        Group::Bn254 => (*self.data.bn254).eq(&other.data.bn254),
                        Group::Ed25519 => (*self.data.ed25519).eq(&other.data.ed25519),
                        _ => todo!(),
                    }
                }
            }
        }

        impl #name {
            pub fn new() -> Self {
                Self { value:ECP::generator() }
            }
        }*/
    };

    TokenStream::from(expanded)
}
*/
