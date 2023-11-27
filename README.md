# Criptografia_2023-24

## Objetivos

### Generales

1. Autenticación de usuarios
2. Cifrado/descifrado simétrico (o asimétrico)
3. Generación/verificación de etiquetas de autenticación de mensajes (e.g., con funciones hash y HMAC)
4. Generación/verificación de firma digital
5. Autenticación de las claves públicas mediante certificados (despliegue de PKI)

En todo momento es necesario utilizar algoritmos que se utilicen en la actualidad y que no hayan
sido comprometidos. Así, por ejemplo, DES no se debe utilizar, debiéndose utilizar AES en su
lugar.

### Fase 1

| Checmark | Tarea                                | Puntuación |
| -------- | ------------------------------------ | ---------- |
| &#9745;      | Autenticación de usuarios            | 1          |
| &#9745;      | Cifrado simétrico/asimétrico         | 0.75         |
| &#9745;      | Etiquetas de autenticación de mensajes| 0.75         |
|  &#9745; | Memoria                              | 1          |
|  &#9745;    | Defensa                              | 1.5          |

#### Autenticación de usuarios

Hemos empleado una autenticacion de usuarios basada en algo que sabemos: contraseñas; se almacenan convenientemente y **a
ser posible que sean robustas**. Esta será la opción que se requerirá que se implemente
en todos los casos como mínimo.

- [ ] **Posible mejora futura con doble autenticación**

#### Cifrado simétrico/asimétrico

En algún momento, en el sistema a desarrollar se tiene que producir un cifrado y descifrado de
información, pudiéndose ver el resultado de dichas operaciones. Nótese que, si el cifrado (o
cualquiera de las operaciones criptográficas siguientes) se aplica, por ejemplo, en
comunicaciones o es transparente para el usuario, se ha de mostrar el resultado en un log o en
un mensaje de depuración, junto con el tipo de algoritmo y la longitud de clave utilizada.
En lo referente a la generación de claves hay que considerar lo siguiente:
 Las claves han de tener una longitud apropiada y en relación con el algoritmo que se
esté utilizando.

#### Generación/verificación de etiquetas de autenticación de mensajes

La información de valor que se intercambie o almacene además de cifrada debe estar
autenticada. Los algoritmos de códigos (o etiquetas) de autenticación de mensajes proporcionan
este servicio.

### Fase 2

| Checmark | Tarea                                      | Puntuación |
| -------- | ------------------------------------       | ---------- |
| &#9744; | Generación/verificación de firma digital    | 1          |
| &#9744; | Certificados y PKI                          | 1          |
| &#9744; | Complejidad y diseño de la aplicación desarrollada | 0.5 |
| &#9744; | Mejoras (opcional)                          | +1         |
| &#9744; | Memoria                                     | 1          |
| &#9744; | Defensa                                     | 1.5        |
