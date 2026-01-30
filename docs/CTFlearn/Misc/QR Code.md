---
custom_edit_url: null
---

> Do you remember something known as QR Code? Simple. Here for you : <br /> https://mega.nz/#!eGYlFa5Z!8mbiqg3kosk93qJCP-DBxIilHH2rf7iIVY-kpwyrx-0

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/81d22ea1-2318-495c-8548-1b0468fb3e81)
</figure>

Let's download the QR code and use Cyberchef to parse it.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/e302c23b-6cd8-4b30-bee1-8e236710852e)
</figure>

Looks like the output is encrypted using Base64. The `==` at the end give it away.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/638afb9a-d028-4be2-b889-3ffbb4c2c8be)
</figure>

This looks like a ROT13 encryption.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/8528b77e-7b25-48b2-b660-b866bfe473cf)
</figure>

## Flag
```
CTFlearn{n0_body_f0rget_qr_code}
```
