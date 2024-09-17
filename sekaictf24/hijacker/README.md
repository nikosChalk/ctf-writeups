# Hijacker

Categories: Android

Description:
>I heard 4-digits pin is insecure, so I made a 6-digits pin system with custom keyboard to prevent keylogger for my android application.
>
>You are required to create a malicious application to solve this challenge, that is by stealing the user's application PIN. Please submit your APK file to the [POC Tester](https://hijacker.chals.sekai.team/) once you have created a working solution.
>
>Note: The POC Tester will first run your malicious application and then the vulnerable application to simulate user interaction in real life. Any permission in your malicious application will be automatically granted. Submit the correct PIN to the connection below to get the flag.
>
>`ncat --ssl hijacker.chals.sekai.team 1337`
> 
>author: Marc
>
>[secure_app.apk](resources/secure_app.apk)

**Tags:** Android, overlays

## Takeaways

* Android overlays PoC

## Solution

The clue is: "*Any permission in your malicious application will be automatically granted*".

1. POC Tester starts our malicious app.
2. Malicious app request permission for overlays and the POC Tester will grant it.
3. POC Tester will switch to benign app.
4. Benign app has no `FLAG_SECURE` or randomized PIN pad.
5. Our malicious app will launch an overlay activity from a foreground service. There are [some restrictions](https://developer.android.com/guide/components/activities/background-starts#exceptions) when doing this, but all are satisfied with our setup.
6. The overlay will mimic the benign's app UI in order to capture the PIN and display it on the overlay.
7. The POC Tester takes a screensot after a few seconds and presents it to us.

The complete malicious app can be found in the [solution](./solution) directory.

When the challenge was presented, the Android version was unknown, but we assumed that overlays might work. After writing the overlay POC, we firgured out that the Android version was 10 (API level 29).

Also the POC Tester had no internet access.

An alternative way is to just straight up read the benign app's code from our malicious app (yes that is possible) and extract the PIN. Then, to exfiltrate the PIN we can be creative, like using overlays, notifications, etc. which will be shown in the final screenshot.

Obligatory flag: `SEKAI{Ev3ry_K3yb0ard_1s_Ins3cur3}`
