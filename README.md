# AutoProx
Automated Proxmark3 actions for pentesting/physical engagements

Need to use a proxmark to steal some badge data but you dont want to keep pressing buttons and rerunning commands? Same. 

`autoprox` automates some of the repetitive and time consuming commands so you can use the proxmark in the field without experiencing any hiccups. 

## Features
- Continuous scanning of LF/HF cards
- Logs relevant card data to disk
- Parses logs for ezpz card forging

### Caveats
Currently, `autoprox` does not perform full dumps of LF/HF cards. Instead, it will attempt to read FC/CN (LF) and UID (HF) and write them to new cards to get around basic access control systems. This is for two reasons. First, scanning basic card data like that is very quick and therefore will allow for minimal contact time with HF antennas (dumping takes slightly longer). Secondly, it is because I am so sleepy. 

For HF cards, the current scanning functionality is geared towards MIFARE 1k ISO14443A, which is extremely common. 

For LF cards, HID cards are prioritized for development bc they are so abundant. 

### Future Plans
- Adding support for card data dumping and autopwn feature (this will be released soon)
- Improved handling for different types of HF card types (I am limited with what I can purchase to build support for these cards)