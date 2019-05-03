{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (lift, liftIO)
import           Servant             ((:>), HasServer (..), Proxy (..),
                                      HasContextEntry(getContextEntry))
import           Servant.Auth

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal (DelayedM, addAuthCheck, withRequest)
import Snap.Core (MonadSnap)

instance ( n ~ 'S ('S 'Z)
         , MonadSnap m
         , HasServer (AddSetCookiesApi n api) ctxs m, AreAuths m auths ctxs v
         , HasServer api ctxs m -- this constraint is needed to implement hoistServer
         , AddSetCookies n (ServerT api ctxs m) (ServerT (AddSetCookiesApi n api) ctxs m)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         ) => HasServer (Auth auths v :> api) ctxs m where
  type ServerT (Auth auths v :> api) ctxs m = AuthResult v -> ServerT api ctxs m

#if MIN_VERSION_servant_snap(0,12,0)
  hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy :: Proxy api) pc nt . s
#endif

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedM m (AuthResult v, SetCookieList ('S ('S 'Z)))
      authCheck = withRequest $ \req -> do
        authResult <- lift $ runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        cookies <- liftIO $ makeCookies authResult
        return (authResult, cookies)

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      makeCookies :: AuthResult v -> IO (SetCookieList ('S ('S 'Z)))
      makeCookies authResult = do
        xsrf <- makeXsrfCookie cookieSettings
        fmap (Just xsrf `SetCookieCons`) $
          case authResult of
            (Authenticated v) -> do
              ejwt <- makeSessionCookie cookieSettings jwtSettings v
              case ejwt of
                Nothing  -> return $ Nothing `SetCookieCons` SetCookieNil
                Just jwt -> return $ Just jwt `SetCookieCons` SetCookieNil
            _ -> return $ Nothing `SetCookieCons` SetCookieNil

      go :: ( old ~ ServerT api ctxs m
            , new ~ ServerT (AddSetCookiesApi n api) ctxs m
            )
         => (AuthResult v -> ServerT api ctxs m)
         -> (AuthResult v, SetCookieList n) -> new
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult