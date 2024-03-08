#![recursion_limit = "256"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use proc_macro::Ident;
use quote::{quote, ToTokens, TokenStreamExt};
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

#[proc_macro_derive(GroupOperations, attributes(supports_pairings, no_pairings))]
pub fn derive_group_operations(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident.clone();

    let mut groups: Vec<syn::Ident> = Vec::new();
    let mut pairing_groups: Vec<syn::Ident> = Vec::new();
    let mut non_pairing_groups: Vec<syn::Ident> = Vec::new();

    match input.data.clone() {
        syn::Data::Enum(s) => {
            groups = s.variants.iter().map(|f| f.ident.clone()).collect();
            for group in s.variants.iter() {
                if let Some(g) = group
                    .attrs
                    .iter()
                    .find(|a| a.path.is_ident("supports_pairings"))
                {
                    pairing_groups.push(group.ident.clone());
                }

                /*if let Some(g) = group.attrs.iter().find(|a| a.path.is_ident("no_pairings")) {
                    non_pairing_groups.push(group.ident.clone());
                }*/
            }
        }
        _ => {
            return TokenStream::new();
        }
    };

    non_pairing_groups = groups
        .iter()
        .filter(|g| !pairing_groups.contains(&g))
        .map(|g| g.clone())
        .collect();

    let f1 = groups.clone();
    let f2 = groups.clone();
    let fields1 = groups.clone();
    let fields2 = groups.clone();
    let fields3 = groups.clone();
    let fields4 = groups.clone();
    let fields5 = groups.clone();
    let fields6 = groups.clone();
    let fields7 = groups.clone();
    let fields8 = groups.clone();
    let fields9 = groups.clone();
    let fields10 = groups.clone();
    let fields11 = groups.clone();
    let fields12 = groups.clone();
    let fields13 = groups.clone();
    let fields14 = groups.clone();
    let fields15 = groups.clone();
    let fields16 = groups.clone();
    let fields17 = groups.clone();
    let fields18 = groups.clone();
    let fields19 = groups.clone();
    let fields20 = groups.clone();
    let fields27 = groups.clone();

    let pfields1 = pairing_groups.clone();
    let pfields2 = pairing_groups.clone();
    let pfields3 = pairing_groups.clone();
    let pfields4 = pairing_groups.clone();
    let pfields5 = pairing_groups.clone();
    let pfields6 = pairing_groups.clone();
    let pfields7 = pairing_groups.clone();
    let pfields8 = pairing_groups.clone();
    let pfields9 = pairing_groups.clone();
    let pfields10 = pairing_groups.clone();
    let pfields11 = pairing_groups.clone();
    let pfields12 = pairing_groups.clone();
    let pfields13 = pairing_groups.clone();
    let pfields14 = pairing_groups.clone();
    let pfields15 = pairing_groups.clone();
    let nfields1 = non_pairing_groups.clone();
    let nfields2 = non_pairing_groups.clone();
    let nfields3 = non_pairing_groups.clone();

    let expanded = quote! {
            impl PartialEq for #name {
                fn eq(&self, other: &Self) -> bool {
                    if mem::discriminant(self) != mem::discriminant(other) {
                        return false;
                    }

                    match self {
                        #(Self::#f1(x) => {
                            if let Self::#f2(y) = other {
                                return x.eq(y);
                            }
                        }),*
                        _ => {
                            return false;
                        }
                    }

                    return false;
                }
            }

        impl GroupOperations for #name {
            fn identity(group: &Group) -> Self {
                match group {
                    #(Group::#fields1 => {Self::#fields2(#fields3::identity())}),*
                    _ => {panic!("unsupported group")},
                }
            }

            fn cmp_group(&self, other: &Self) -> bool {
                mem::discriminant(self) == mem::discriminant(other)
            }

            fn is_type(&self, group: &Group) -> bool {
                match group {
                    #(Group::#fields4 => {
                        if let Self::#fields5(x) = self {
                            return true
                        }
                    }),*
                    _ => return false
                }

                return false;
            }

            fn get_group(&self) -> &Group {
                match self {
                    #(Self::#fields6(x) => &Group::#fields7),*
                }
            }

            fn new(group: &Group) -> Self {
                match group {
                    #(Group::#fields8 => {Self::#fields9(#fields10::new())}),*
                    _ => {panic!("unsupported group")},
                }
            }

            fn new_ecp2(group: &Group) -> Self {
                match group {
                    #(Group::#pfields4 => {Self::#pfields5(#pfields6::new_ecp2())}),*
                    _ => panic!("group does not support pairings"),
                }
            }

            fn pair(&self, y: &Self) -> Self {
                if !self.get_group().supports_pairings() {
                    panic!("group does not support pairings");
                }

                if !self.cmp_group(&y) {
                    panic!("incompatible groups");
                }

                match self {
                    #(Self::#pfields7(_x) => {
                        if let Self::#pfields8(_y) = y {
                            return Self::#pfields9(#pfields10::pair(_x, _y).unwrap());
                        }
                    }),*
                    _ => {
                        panic!();
                    }
                }

                panic!();
            }

            fn ddh(
                x: &GroupElement,
                y: &GroupElement,
                z: &GroupElement,
                w: &GroupElement,
            ) -> Result<bool, SchemeError> {
                if !x.get_group().supports_pairings() {
                    panic!("group does not support pairings");
                }

                if !x.cmp_group(&y) || !y.cmp_group(&z) || !z.cmp_group(&w) {
                    panic!("incompatible groups");
                }

                match x {
                    #(Self::#pfields11(_x) => {
                        if let Self::#pfields12(_y) = y {
                            if let Self::#pfields13(_z) = z {
                                if let Self::#pfields14(_w) = w {
                                    return #pfields15::ddh(&_x, &_y, &_z, &_w);
                                }
                            }
                        }
                    }),*
                    _ => {
                        panic!();
                    }
                }

                panic!();
            }

            fn new_hash(group: &Group, hash: &[u8]) -> Self {
                match group {
                    Group::Bls12381 => {
                        return Self::Bls12381(Bls12381::new_from_ecp(
                            mcore::bls12381::bls::bls_hash_to_point(hash),
                        ));
                    },
                    Group::Bn254 => {
                        return Self::Bn254(Bn254::new_from_ecp(mcore::bn254::bls::bls_hash_to_point(
                            hash,
                        )));
                    },
                    _ => panic!("group does not support hash to point"),
                }
            }

            fn new_pow_big(group: &Group, y: &SizedBigInt) -> Self {
                match group {
                    #(Group::#fields11 => {
                        return Self::#fields12(#fields13::new_pow_big(y));
                    }),*
                    _ => panic!("unsupported group")
                }
            }

            fn new_pow_big_ecp2(group: &Group, y: &SizedBigInt) -> Self {
                match group {
                    Group::Bls12381 => {
                        return Self::Bls12381(Bls12381::new_pow_big_ecp2(y));
                    },
                    Group::Bn254 => {
                        return Self::Bn254(Bn254::new_pow_big_ecp2(y));
                    },
                    _ => panic!("group does not support extensions")
                }
            }

            fn new_rand(group: &Group, rng: &mut RNG) -> Self {
                match group {
                    #(Group::#fields14 => {
                        return Self::#fields15(#fields16::new_rand(rng));
                    }),*
                    _ => panic!("unsupported group")
                }
            }

            fn mul(&self, y: &Self) -> Self {
                if !Self::cmp_group(&self, y) {
                    panic!("incompatible groups!");
                }

                match self {
                    Self::Bls12381(_x) => {
                        if let Self::Bls12381(_y) = y {
                            return _x.mul(_y);
                        }
                    },
                    Self::Bn254(_x) => {
                        if let Self::Bn254(_y) = y {
                            return _x.mul(_y);
                        }
                    },
                    Self::Ed25519(_x) => {
                        if let Self::Ed25519(_y) = y {
                            return _x.mul(_y);
                        }
                    },
                    _ => todo!(),
                }

                panic!("incompatible groups");
            }

            fn div(&self, y: &Self) -> Self {
                if !Self::cmp_group(&self, y) {
                    panic!("incompatible groups!");
                }

                match self {
                    Self::Bls12381(_x) => {
                        if let Self::Bls12381(_y) = y {
                            return _x.div(_y);
                        }
                    },
                    Self::Bn254(_x) => {
                        if let Self::Bn254(_y) = y {
                            return _x.div(_y);
                        }
                    },
                    Self::Ed25519(_x) => {
                        if let Self::Ed25519(_y) = y {
                            return _x.div(_y);
                        }
                    },
                    _ => todo!(),
                }

                panic!("incompatible groups");
            }

            fn pow(&self, y: &SizedBigInt) -> Self {
                match self {
                    #(Self::#fields17(x) => {
                        return x.pow(y);
                    }),*
                }
            }

            fn get_order(&self) -> SizedBigInt {
                match self {
                    #(Self::#fields18(_) => #fields27::get_order()),*
                }
            }

            fn to_bytes(&self) -> Vec<u8> {
                unsafe {
                    match self {
                        #(Self::#fields19(x) => x.to_bytes()),*
                    }
                }
            }

            fn to_string(&self) -> String {
                unsafe {
                    match self {
                        #(Self::#fields20(x) => x.to_string()),*
                    }
                }
            }

            fn from_bytes(bytes: &[u8], group: &Group, i: Option<u8>) -> Self {
                let mut j = 0;
                if i.is_some() {
                    j = i.unwrap();
                }

                match group {
                    #(Group::#pfields1 => {return Self::#pfields2(#pfields3::from_bytes(bytes, j))}),*
                    #(Group::#nfields1 => {return Self::#nfields2(#nfields3::from_bytes(bytes))}),*
                    _ => panic!("unsupported group")
                }
            }
        }
    };
    TokenStream::from(expanded)
}
