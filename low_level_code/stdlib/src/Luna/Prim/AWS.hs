{-# LANGUAGE OverloadedStrings #-}

module Luna.Prim.AWS where

import           Prologue

import qualified Data.Map                    as Map
import qualified Luna.IR                     as IR
import qualified Luna.Pass.Sourcing.Data.Def as Def
import qualified Luna.Runtime                as Luna
import qualified Luna.Std.Builder            as Builder

import           Data.Map                    (Map)
import           Luna.Std.Builder            ( makeFunctionIO
                                             )

import qualified Network.AWS as AWS
import qualified Network.AWS.Lambda as Lambda

exports :: forall graph m. Builder.StdBuilder graph m => m (Map IR.Name Def.Def)
exports = do
    let listFunsVal :: IO ()
        listFunsVal = do
          env <- AWS.newEnv
            $ AWS.FromEnv "AWS_ACCESS_KEY" "AWS_SECRET_KEY" Nothing (Just "AWS_REGION")
          funs <- AWS.runResourceT $ AWS.runAWS env
            $ AWS.send
            $ Lambda.listFunctions
          print funs
    primListFuns <- makeFunctionIO @graph (flip Luna.toValue listFunsVal) [] Builder.noneLT

    return $ Map.fromList [ ("primListFuns", primListFuns) ]
