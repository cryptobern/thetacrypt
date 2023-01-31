/// ---------- Decrypt a ciphertext ----------
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptRequest {
    #[prost(bytes="vec", tag="1")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, optional, tag="2")]
    pub key_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptReponse {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptSyncRequest {
    #[prost(bytes="vec", tag="1")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, optional, tag="2")]
    pub key_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptSyncReponse {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
    #[prost(bytes="vec", optional, tag="2")]
    pub plaintext: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetDecryptResultRequest {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetDecryptResultResponse {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
    #[prost(bool, tag="2")]
    pub is_started: bool,
    #[prost(bool, tag="3")]
    pub is_finished: bool,
    #[prost(bytes="vec", optional, tag="4")]
    pub plaintext: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// ---------- Get available keys ----------
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyEntry {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration="super::scheme_types::ThresholdScheme", tag="2")]
    pub scheme: i32,
    #[prost(enumeration="super::scheme_types::Group", tag="3")]
    pub group: i32,
    /// bool is_default = 3;
    #[prost(bytes="vec", tag="4")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysForEncryptionRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysForEncryptionResponse {
    #[prost(message, repeated, tag="1")]
    pub keys: ::prost::alloc::vec::Vec<PublicKeyEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysForSignatureRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysForSignatureResponse {
    #[prost(message, repeated, tag="1")]
    pub keys: ::prost::alloc::vec::Vec<PublicKeyEntry>,
}
/// ---------- Push decryption share, test only ----------
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PushDecryptionShareRequest {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="2")]
    pub decryption_share: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PushDecryptionShareResponse {
}
/// Generated client implementations.
pub mod threshold_crypto_library_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct ThresholdCryptoLibraryClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ThresholdCryptoLibraryClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ThresholdCryptoLibraryClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ThresholdCryptoLibraryClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            ThresholdCryptoLibraryClient::new(
                InterceptedService::new(inner, interceptor),
            )
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// decrypt returns as soons as the decryption protocol is started. It returns only the instance_id of the newly started protocol instance.
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::DecryptRequest>,
        ) -> Result<tonic::Response<super::DecryptReponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/protocol_types.ThresholdCryptoLibrary/decrypt",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Returns the result of a protocol instance
        pub async fn get_decrypt_result(
            &mut self,
            request: impl tonic::IntoRequest<super::GetDecryptResultRequest>,
        ) -> Result<tonic::Response<super::GetDecryptResultResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/protocol_types.ThresholdCryptoLibrary/get_decrypt_result",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// decrypt_sync waits for the decryption instance to finish and returns the decrypted plaintext
        pub async fn decrypt_sync(
            &mut self,
            request: impl tonic::IntoRequest<super::DecryptSyncRequest>,
        ) -> Result<tonic::Response<super::DecryptSyncReponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/protocol_types.ThresholdCryptoLibrary/decrypt_sync",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn get_public_keys_for_encryption(
            &mut self,
            request: impl tonic::IntoRequest<super::GetPublicKeysForEncryptionRequest>,
        ) -> Result<
            tonic::Response<super::GetPublicKeysForEncryptionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/protocol_types.ThresholdCryptoLibrary/get_public_keys_for_encryption",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        ///this is an alternative way to send shares. used only for testing
        pub async fn push_decryption_share(
            &mut self,
            request: impl tonic::IntoRequest<super::PushDecryptionShareRequest>,
        ) -> Result<tonic::Response<super::PushDecryptionShareResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/protocol_types.ThresholdCryptoLibrary/push_decryption_share",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod threshold_crypto_library_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with ThresholdCryptoLibraryServer.
    #[async_trait]
    pub trait ThresholdCryptoLibrary: Send + Sync + 'static {
        /// decrypt returns as soons as the decryption protocol is started. It returns only the instance_id of the newly started protocol instance.
        async fn decrypt(
            &self,
            request: tonic::Request<super::DecryptRequest>,
        ) -> Result<tonic::Response<super::DecryptReponse>, tonic::Status>;
        /// Returns the result of a protocol instance
        async fn get_decrypt_result(
            &self,
            request: tonic::Request<super::GetDecryptResultRequest>,
        ) -> Result<tonic::Response<super::GetDecryptResultResponse>, tonic::Status>;
        /// decrypt_sync waits for the decryption instance to finish and returns the decrypted plaintext
        async fn decrypt_sync(
            &self,
            request: tonic::Request<super::DecryptSyncRequest>,
        ) -> Result<tonic::Response<super::DecryptSyncReponse>, tonic::Status>;
        async fn get_public_keys_for_encryption(
            &self,
            request: tonic::Request<super::GetPublicKeysForEncryptionRequest>,
        ) -> Result<
            tonic::Response<super::GetPublicKeysForEncryptionResponse>,
            tonic::Status,
        >;
        ///this is an alternative way to send shares. used only for testing
        async fn push_decryption_share(
            &self,
            request: tonic::Request<super::PushDecryptionShareRequest>,
        ) -> Result<tonic::Response<super::PushDecryptionShareResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct ThresholdCryptoLibraryServer<T: ThresholdCryptoLibrary> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: ThresholdCryptoLibrary> ThresholdCryptoLibraryServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>>
    for ThresholdCryptoLibraryServer<T>
    where
        T: ThresholdCryptoLibrary,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/protocol_types.ThresholdCryptoLibrary/decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct decryptSvc<T: ThresholdCryptoLibrary>(pub Arc<T>);
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<super::DecryptRequest>
                    for decryptSvc<T> {
                        type Response = super::DecryptReponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DecryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).decrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = decryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/protocol_types.ThresholdCryptoLibrary/get_decrypt_result" => {
                    #[allow(non_camel_case_types)]
                    struct get_decrypt_resultSvc<T: ThresholdCryptoLibrary>(pub Arc<T>);
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<super::GetDecryptResultRequest>
                    for get_decrypt_resultSvc<T> {
                        type Response = super::GetDecryptResultResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetDecryptResultRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).get_decrypt_result(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = get_decrypt_resultSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/protocol_types.ThresholdCryptoLibrary/decrypt_sync" => {
                    #[allow(non_camel_case_types)]
                    struct decrypt_syncSvc<T: ThresholdCryptoLibrary>(pub Arc<T>);
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<super::DecryptSyncRequest>
                    for decrypt_syncSvc<T> {
                        type Response = super::DecryptSyncReponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DecryptSyncRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).decrypt_sync(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = decrypt_syncSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/protocol_types.ThresholdCryptoLibrary/get_public_keys_for_encryption" => {
                    #[allow(non_camel_case_types)]
                    struct get_public_keys_for_encryptionSvc<T: ThresholdCryptoLibrary>(
                        pub Arc<T>,
                    );
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<
                        super::GetPublicKeysForEncryptionRequest,
                    > for get_public_keys_for_encryptionSvc<T> {
                        type Response = super::GetPublicKeysForEncryptionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::GetPublicKeysForEncryptionRequest,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).get_public_keys_for_encryption(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = get_public_keys_for_encryptionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/protocol_types.ThresholdCryptoLibrary/push_decryption_share" => {
                    #[allow(non_camel_case_types)]
                    struct push_decryption_shareSvc<T: ThresholdCryptoLibrary>(
                        pub Arc<T>,
                    );
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<super::PushDecryptionShareRequest>
                    for push_decryption_shareSvc<T> {
                        type Response = super::PushDecryptionShareResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PushDecryptionShareRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).push_decryption_share(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = push_decryption_shareSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: ThresholdCryptoLibrary> Clone for ThresholdCryptoLibraryServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: ThresholdCryptoLibrary> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: ThresholdCryptoLibrary> tonic::server::NamedService
    for ThresholdCryptoLibraryServer<T> {
        const NAME: &'static str = "protocol_types.ThresholdCryptoLibrary";
    }
}
