#!/usr/bin/env python3
"""Builds the HARMLESS synthetic Phase 8 fixtures in tests/fixtures (committed; re-run only if you change them).
All text is synthetic. Domains use reserved example/test names or documentation IP ranges (RFC 5737). No real malware, no live URLs.
Requires: pip install pillow qrcode reportlab"""
import os, io
from PIL import Image, ImageDraw, ImageFont
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

OUT = os.path.join(os.path.dirname(__file__), '..', 'fixtures')
FD = '/usr/share/fonts/truetype/dejavu/'
def font(sz, bold=False): return ImageFont.truetype(FD + ('DejaVuSans-Bold.ttf' if bold else 'DejaVuSans.ttf'), sz)

def text_image(lines, w=1400, bg=(255, 255, 255), fg=(20, 20, 20), size=40, title=None, qr=None, h=None):
    step = int(size * 1.55)
    h = h or (120 + step * (len(lines) + (2 if title else 0)) + (420 if qr else 0))
    im = Image.new('RGB', (w, h), bg); d = ImageDraw.Draw(im); y = 50
    if title: d.text((60, y), title, fill=fg, font=font(size + 14, True)); y += int(size * 2.4)
    for l in lines: d.text((60, y), l, fill=fg, font=font(size)); y += step
    if qr: im.paste(qr, (60, y + 20))
    return im

def qr_img(payload, box=9):
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=4); q.add_data(payload); q.make(fit=True)
    return q.make_image(fill_color='black', back_color='white').convert('RGB')

PHISH_LINES = ['Your account will be suspended within 24 hours.', 'Verify your account immediately to avoid closure.', 'Enter your password and OTP at the link below:', 'https://secure-login.account-verify.example.test/verify']
NORMAL_LINES = ['Team lunch is on Friday at noon in the main cafeteria.', 'Please bring your own water bottle.', 'The quarterly planning meeting moves to Tuesday.']

# ---- images
ph = text_image(PHISH_LINES, title='SECURITY ALERT'); ph.save(f'{OUT}/test-phishing-image.png')
ph.save(f'{OUT}/test-phishing-image.jpg', quality=90); ph.save(f'{OUT}/test-phishing-image.webp', quality=90)
nm = text_image(NORMAL_LINES, title='Office Notes'); nm.save(f'{OUT}/test-normal-image.png'); nm.save(f'{OUT}/test-normal-image.jpg', quality=90); nm.save(f'{OUT}/test-normal-image.webp', quality=90)
text_image(['Invoice 4471 - payment required today.', 'Urgent: confirm your account details.', 'Enter your OTP at the page behind the QR code.'], title='INVOICE', qr=qr_img('https://paypal-secure-login.example.test/verify/account'), w=1400).save(f'{OUT}/test-qr-phishing.png')
text_image(['Scan the code for the lunch menu.'], title='Cafeteria', qr=qr_img('https://menu.example.org/lunch'), w=1400).save(f'{OUT}/test-qr-benign.png')
text_image(['Wi-Fi guest access'], title='Guest network', qr=qr_img('WIFI:T:WPA;S:GuestNet;P:not-a-real-password;;'), w=1400).save(f'{OUT}/test-qr-wifi.png')
text_image(['Note to self: buy milk and bread.'], title='Reminder', qr=qr_img('Just some plain text in a QR code'), w=1400).save(f'{OUT}/test-qr-text.png')
two = Image.new('RGB', (1400, 520), 'white'); two.paste(qr_img('https://one.example.org/a', 8), (40, 40)); two.paste(qr_img('https://two-secure-login.example.test/verify', 8), (700, 40)); two.save(f'{OUT}/test-qr-multi.png')
# large image (5000x3500, text readable at the OCR working size) to exercise safe downsampling
big = text_image(['QUARTERLY PLANNING NOTES', 'Please review the budget before Friday.', 'Send the roadmap to the leadership group.'], w=5000, h=3500, size=150); big.save(f'{OUT}/test-large-image.png', optimize=True)
open(f'{OUT}/test-corrupt-image.png', 'wb').write(open(f'{OUT}/test-normal-image.png', 'rb').read()[:900] + b'\x00' * 300)

# ---- PDFs
def img_buf(im, fmt):
    b = io.BytesIO(); im.save(b, fmt, **({'quality': 90} if fmt == 'JPEG' else {})); b.seek(0); return ImageReader(b)
def full_page(c, im):
    W, H = letter; r = im.width / im.height; w = W - 60; h = w / r
    if h > H - 60: h = H - 60; w = h * r
    c.drawImage(img_buf(im, 'JPEG' if getattr(im, '_dct', False) else 'PNG'), 30, H - 30 - h, w, h)
def pdf(path, pages):
    c = canvas.Canvas(path, pagesize=letter); c.setTitle('Synthetic test document')
    for p in pages:
        kind, val = p
        if kind == 'text':
            c.setFont('Helvetica', 12); y = 740
            for l in val: c.drawString(60, y, l); y -= 18
        elif kind == 'img': full_page(c, val)
        elif kind == 'textimg':
            c.setFont('Helvetica', 12); y = 740
            for l in val[0]: c.drawString(60, y, l); y -= 18
            c.drawImage(img_buf(val[1], 'PNG'), 60, 300, 260, 260)
        c.showPage()
    c.save()
dct = text_image(PHISH_LINES, title='SECURITY ALERT', w=1400); dct._dct = True
pdf(f'{OUT}/test-scanned-phishing.pdf', [('img', dct)])
pdf(f'{OUT}/test-normal-scanned-document.pdf', [('img', text_image(NORMAL_LINES, title='Office Notes', w=1400)), ('img', text_image(['Second page of the scanned memo.', 'Nothing unusual here.'], w=1400))])
pdf(f'{OUT}/test-mixed-phishing.pdf', [('text', ['Quarterly update', 'This page has normal selectable text.']), ('img', text_image(['Verify your account immediately.', 'Enter your password and OTP here:', 'https://secure-login.account-verify.example.test/verify'], title='SECURITY ALERT')), ('text', ['Appendix A', 'More normal selectable text on page three.']), ('img', text_image(['Your account will be suspended within 24 hours.', 'Confirm your account details now.']))])
pdf(f'{OUT}/test-pdf-qr.pdf', [('text', ['Invoice 4471', 'Payment required. Scan the code to pay and verify your account.']), ('textimg', (['Scan to pay'], qr_img('https://paypal-secure-login.example.test/verify/account')))])
pdf(f'{OUT}/test-pdf-text-and-same-ocr.pdf', [('text', ['URGENT: verify your account immediately.', 'Enter your password and OTP at https://secure-login.account-verify.example.test/verify']), ('img', text_image(['URGENT: verify your account immediately.', 'Enter your password and OTP at', 'https://secure-login.account-verify.example.test/verify']))])
pdf(f'{OUT}/test-text-only.pdf', [('text', ['Meeting agenda', 'Item 1: budget review.', 'Item 2: roadmap.'])])
pdf(f'{OUT}/test-multipage-scanned.pdf', [('img', text_image([f'Scanned page number {i}.', 'Ordinary memo content only.'], w=1400)) for i in range(1, 15)])
print('fixtures written to', os.path.abspath(OUT))
