import cv2

# Load the QR code image
img = cv2.imread('qrcode.png')

# Convert the image to grayscale
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

# Create a QR code detector
detector = cv2.QRCodeDetector()

# Detect and decode the QR code
data, bbox, _ = detector.detectAndDecode(gray)

# Print the decoded data
if data:
  print("Data:", data)
else:
  print("No QR code found")
