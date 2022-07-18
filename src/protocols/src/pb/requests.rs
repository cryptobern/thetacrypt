#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdDecryptionRequest {
    /// ThresholdCipher algorithm = 1;
    /// DlGroup dl_group = 2;
    #[prost(bytes="vec", tag="1")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, optional, tag="2")]
    pub key_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdDecryptionResponse {
    #[prost(string, tag="1")]
    pub instance_id: ::prost::alloc::string::String,
}
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
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        #[must_use]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::ThresholdDecryptionRequest>,
        ) -> Result<tonic::Response<super::ThresholdDecryptionResponse>, tonic::Status> {
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
                "/requests.ThresholdCryptoLibrary/decrypt",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
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
                "/requests.ThresholdCryptoLibrary/push_decryption_share",
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
        async fn decrypt(
            &self,
            request: tonic::Request<super::ThresholdDecryptionRequest>,
        ) -> Result<tonic::Response<super::ThresholdDecryptionResponse>, tonic::Status>;
        async fn push_decryption_share(
            &self,
            request: tonic::Request<super::PushDecryptionShareRequest>,
        ) -> Result<tonic::Response<super::PushDecryptionShareResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct ThresholdCryptoLibraryServer<T: ThresholdCryptoLibrary> {
        inner: _Inner<T>,
        accept_compression_encodings: (),
        send_compression_encodings: (),
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
                "/requests.ThresholdCryptoLibrary/decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct decryptSvc<T: ThresholdCryptoLibrary>(pub Arc<T>);
                    impl<
                        T: ThresholdCryptoLibrary,
                    > tonic::server::UnaryService<super::ThresholdDecryptionRequest>
                    for decryptSvc<T> {
                        type Response = super::ThresholdDecryptionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ThresholdDecryptionRequest>,
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
                "/requests.ThresholdCryptoLibrary/push_decryption_share" => {
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
    impl<T: ThresholdCryptoLibrary> tonic::transport::NamedService
    for ThresholdCryptoLibraryServer<T> {
        const NAME: &'static str = "requests.ThresholdCryptoLibrary";
    }
}
