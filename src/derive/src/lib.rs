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