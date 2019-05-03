{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.ThrowAll where

#if !MIN_VERSION_servant_snap(0,16,0)
#define ServerError ServantErr
#endif

import Control.Monad.Error.Class
import Data.Monoid.Endo
import Data.Tagged               (Tagged (..))
import Servant                   ((:<|>) (..), ServerError(..))
import Snap.Core

import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as LBS

class ThrowAll a where
  -- | 'throwAll' is a convenience function to throw errors across an entire
  -- sub-API
  --
  --
  -- > throwAll err400 :: Handler a :<|> Handler b :<|> Handler c
  -- >    == throwError err400 :<|> throwError err400 :<|> err400
  throwAll :: ServerError -> a

instance (ThrowAll a, ThrowAll b) => ThrowAll (a :<|> b) where
  throwAll e = throwAll e :<|> throwAll e

-- Really this shouldn't be necessary - ((->) a) should be an instance of
-- MonadError, no?
instance {-# OVERLAPPING #-} ThrowAll b => ThrowAll (a -> b) where
  throwAll e = throwAll e

instance {-# OVERLAPPABLE #-} (MonadError ServerError m) => ThrowAll (m a) where
  throwAll = throwError

-- | for @servant <0.11@
instance {-# OVERLAPPING #-} ThrowAll (Snap a) where
  throwAll = throwAllSnap

-- | for @servant >=0.11@
instance {-# OVERLAPPING #-} MonadError ServerError m => ThrowAll (Tagged m (Snap a)) where
  throwAll e = Tagged $ throwAllSnap e

throwAllSnap :: MonadSnap m => ServantErr -> m b
throwAllSnap e = do
  modifyResponse
    $ setResponseStatus (errHTTPCode e) (BS.pack $ errReasonPhrase e)
    . (appEndo $ foldMap (\(hn,hv) -> Endo $ addHeader hn hv) (errHeaders e))
  writeBS (LBS.toStrict $ errBody e)
  r <- getResponse
  finishWith r
