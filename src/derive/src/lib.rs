extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;
use syn::Ident;

#[proc_macro_derive(PublicKey)]
pub fn public_key_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::interface::PublicKey for #name #ty_generics #where_clause {}

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

            fn get_id(&self) -> usize {
                self.id
            }

            fn get_public_key(&self) -> Self::TPubKey {
                self.pubkey.clone()
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
        impl #impl_generics crate::interface::PublicKey for #name #ty_generics #where_clause {}

        impl #impl_generics crate::interface::Serializable for #name #ty_generics #where_clause {}
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Share)]
pub fn share_derive(input:TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let generics = input.generics;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics Share for #name #ty_generics #where_clause {
            fn get_id(&self) -> usize { self.id.clone() }
        }

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

    let type_param = &generics.type_params().last().unwrap().ident;

    let expanded = quote! {
        impl #impl_generics DlShare #ty_generics for #name #ty_generics #where_clause {
            fn get_data(&self) -> #type_param {
                self.data.clone()
            }
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