{-# LANGUAGE PolyKinds                  #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE CPP                        #-}

module Servant.Auth.Server.Internal.AddSetCookie where

import           Blaze.ByteString.Builder (toByteString)
import           Data.Tagged              (Tagged (..))
import           Servant
import           Snap.Core                (Snap, Response)
import qualified Snap.Core                as Snap
import           Web.Cookie

-- What are we doing here? Well, the idea is to add headers to the response,
-- but the headers come from the authentication check. In order to do that, we
-- tweak a little the general theme of recursing down the API tree; this time,
-- we recurse down a variation of it that adds headers to all the endpoints.
-- This involves the usual type-level checks.
--
-- TODO: If the endpoints already have headers, this will not work as is.

data Nat = Z | S Nat

type family AddSetCookiesApi (n :: Nat) a where
  AddSetCookiesApi ('S 'Z) a = AddSetCookieApi a
  AddSetCookiesApi ('S n) a = AddSetCookiesApi n (AddSetCookieApi a)

type family AddSetCookieApiVerb a where
  AddSetCookieApiVerb (Headers ls a) = Headers (Header "Set-Cookie" SetCookie ': ls) a
  AddSetCookieApiVerb a = Headers '[Header "Set-Cookie" SetCookie] a

type family AddSetCookieApi a :: *
type instance AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
type instance AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
type instance AddSetCookieApi (Verb method stat ctyps a)
  = Verb method stat ctyps (AddSetCookieApiVerb a)
type instance AddSetCookieApi Raw = Raw
#if MIN_VERSION_servant_snap(0,15,0)
type instance AddSetCookieApi (Stream method stat framing ctyps a)
  = Stream method stat framing ctyps (AddSetCookieApiVerb a)
#endif
type instance AddSetCookieApi (Headers hs a) = AddSetCookieApiVerb (Headers hs a)

data SetCookieList (n :: Nat) :: * where
  SetCookieNil :: SetCookieList 'Z
  SetCookieCons :: Maybe SetCookie -> SetCookieList n -> SetCookieList ('S n)

class AddSetCookies (n :: Nat) orig new where
  addSetCookies :: SetCookieList n -> orig -> new

instance {-# OVERLAPS #-} AddSetCookies ('S n) oldb newb
  => AddSetCookies ('S n) (a -> oldb) (a -> newb) where
  addSetCookies cookies oldfn = addSetCookies cookies . oldfn

instance AddSetCookies 'Z orig orig where
  addSetCookies _ = id

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddSetCookies n (m old) (m cookied)
  , AddHeader "Set-Cookie" SetCookie cookied new
  ) => AddSetCookies ('S n) (m old) (m new)  where
  addSetCookies (mCookie `SetCookieCons` rest) oldVal =
    case mCookie of
      Nothing -> noHeader <$> addSetCookies rest oldVal
      Just cookie -> addHeader cookie <$> addSetCookies rest oldVal

instance {-# OVERLAPS #-}
  (AddSetCookies ('S n) a a', AddSetCookies ('S n) b b')
  => AddSetCookies ('S n) (a :<|> b) (a' :<|> b') where
  addSetCookies cookies (a :<|> b) = addSetCookies cookies a :<|> addSetCookies cookies b

-- | for @servant <0.11@
instance
  AddSetCookies ('S n) (Snap ()) (Snap ()) where
  addSetCookies cookies orig
    = do
      orig
      mkHeaders cookies

-- | for @servant >=0.11@
instance
  AddSetCookies ('S n) (Tagged m (Snap ())) (Tagged m (Snap ())) where
  addSetCookies cookies orig = Tagged $ do
    unTagged orig
    mkHeaders cookies

mkHeaders :: SetCookieList x -> Snap ()
mkHeaders cl = Snap.modifyResponse $ mkCookies cl
  where
    mkCookies :: forall y. SetCookieList y -> Response -> Response
    mkCookies SetCookieNil = id
    mkCookies (SetCookieCons Nothing rest) = mkCookies rest
    mkCookies (SetCookieCons (Just y) rest)
      = (Snap.addHeader "Set-Cookie" (toByteString (renderSetCookie y))) . (mkCookies rest)
