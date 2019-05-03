module Servant.Auth.Server.Internal.Types where

import Control.Applicative
import Control.Monad.Reader
import Control.Monad.Time
import Data.Monoid          (Monoid (..))
import Data.Semigroup       (Semigroup (..))
import Data.Time            (getCurrentTime)
import GHC.Generics         (Generic)
import Snap.Core            (Request, MonadSnap)

-- | The result of an authentication attempt.
data AuthResult val
  = BadPassword
  | NoSuchUser
  -- | Authentication succeeded.
  | Authenticated val
  -- | If an authentication procedure cannot be carried out - if for example it
  -- expects a password and username in a header that is not present -
  -- @Indefinite@ is returned. This indicates that other authentication
  -- methods should be tried.
  | Indefinite
  deriving (Eq, Show, Read, Generic, Ord, Functor, Traversable, Foldable)

instance Semigroup (AuthResult val) where
  Indefinite <> y = y
  x          <> _ = x

instance Monoid (AuthResult val) where
  mempty = Indefinite
  mappend = (<>)

instance Applicative AuthResult where
  pure = return
  (<*>) = ap

instance Monad AuthResult where
  return = Authenticated
  Authenticated v >>= f = f v
  BadPassword  >>= _ = BadPassword
  NoSuchUser   >>= _ = NoSuchUser
  Indefinite   >>= _ = Indefinite

instance Alternative AuthResult where
  empty = mzero
  (<|>) = mplus

instance MonadPlus AuthResult where
  mzero = mempty
  mplus = (<>)


-- | An @AuthCheck@ is the function used to decide the authentication status
-- (the 'AuthResult') of a request. Different @AuthCheck@s may be combined as a
-- Monoid or Alternative; the semantics of this is that the *first*
-- non-'Indefinite' result from left to right is used and the rest are ignored.
newtype AuthCheck m val = AuthCheck
  { runAuthCheck :: MonadSnap m => Request -> m (AuthResult val) }
  deriving (Functor)

instance Monad m => Semigroup (AuthCheck m val) where
  AuthCheck f <> AuthCheck g = AuthCheck $ \x -> do
    fx <- f x
    case fx of
      Indefinite -> g x
      r -> pure r

instance Monad m => Monoid (AuthCheck m val) where
  mempty = AuthCheck $ const $ pure mempty
  mappend = (<>)

instance Monad m => Applicative (AuthCheck m) where
  pure = pure
  (<*>) = ap

instance Monad m => Monad (AuthCheck m) where
  return = AuthCheck . return . return . return
  fail _ = AuthCheck . const $ return Indefinite
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Authenticated usr -> runAuthCheck (f usr) req
      BadPassword       -> return BadPassword
      NoSuchUser        -> return NoSuchUser
      Indefinite        -> return Indefinite

instance Monad m => MonadReader Request (AuthCheck m) where
  ask = AuthCheck $ \x -> return (Authenticated x)
  local f (AuthCheck check) = AuthCheck $ \req -> check (f req)

instance MonadIO m => MonadIO (AuthCheck m) where
  liftIO action = AuthCheck $ const $ Authenticated <$> liftIO action

instance MonadIO m => MonadTime (AuthCheck m) where
  currentTime = liftIO getCurrentTime

instance Monad m => Alternative (AuthCheck m) where
  empty = mzero
  (<|>) = mplus

instance Monad m => MonadPlus (AuthCheck m) where
  mzero = mempty
  mplus = (<>)
