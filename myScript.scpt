tell application "Terminal.app"
    activate
    set targetWindow to 0
    do script "cd 
    /Users/bryce/BlockchainD/ && java BlockchainD 0"

    tell application "System Events" to keystroke "t" using command down
    do script "cd
    /Users/bryce/BlockchainD/ && java BlockchainD 1" in window 0

    delay 0.3
    tell application "System Events" to keystroke "t" using command down
    do script "cd
    /Users/bryce/BlockchainD/
    && java BlockchainD 2" in window 0
end tell
