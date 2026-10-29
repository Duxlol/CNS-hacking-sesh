import cv2
import os

# Forceer OpenCV om TCP te gebruiken voor de RTSP-stream (cruciaal voor deze server!)
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"

# Jouw gekraakte URL
url = "rtsp://user:camera123456789@cns-test.idlab.uantwerpen.be:50002/video"

print("[*] Verbinden met de beveiligingscamera...")
cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)

if not cap.isOpened():
    print("[!] Kon de videostream niet openen. (Zit je nog op de VPN?)")
    exit()

print("[+] Verbonden! Druk op de 'q' toets in het videovenster om te stoppen.")

while True:
    # Lees frame voor frame
    ret, frame = cap.read()

    if not ret:
        print("[!] Geen beeld meer ontvangen van de server.")
        break

    # Laat het frame zien in een pop-up venster
    cv2.imshow('Mars Relay Facility Camera', frame)

    # Wacht 1 milliseconde en breek de loop als de 'q' toets wordt ingedrukt
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Sluit de verbinding en het venster netjes af
cap.release()
cv2.destroyAllWindows()