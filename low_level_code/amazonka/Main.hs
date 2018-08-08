{-# LANGUAGE OverloadedStrings #-}

import qualified Network.AWS as AWS
import qualified Network.AWS.Lambda as Lambda

listFuns = do
  env <- AWS.newEnv
    $ AWS.FromEnv "AWS_ACCESS_KEY" "AWS_SECRET_KEY" Nothing (Just "AWS_REGION")
  funs <- AWS.runResourceT $ AWS.runAWS env
    $ AWS.send
    $ Lambda.listFunctions
  print funs

main = listFuns
