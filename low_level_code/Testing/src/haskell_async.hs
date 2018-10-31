{-# LANGUAGE OverloadedStrings #-}

import Control.Lens
import Control.Monad.Parallel

import qualified Data.Time                   as Time
import qualified Network.AWS                 as AWS
import qualified Network.AWS.Lambda          as Lambda

main = do
    env <- AWS.newEnv AWS.Discover <&> AWS.envRegion .~ AWS.NorthVirginia
    let run n = replicateM_ n . AWS.runResourceT . AWS.runAWS env . AWS.send

    start <- Time.getZonedTime
    run 1000 $ Lambda.invoke "testFunc" ""
    end <- Time.getZonedTime

    print $ Time.diffUTCTime (Time.zonedTimeToUTC end) (Time.zonedTimeToUTC start)
