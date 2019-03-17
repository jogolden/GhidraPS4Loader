## Ghidra PS4 Loader by golden

This is a simple module for Ghidra to support loading PlayStation 4 ELF files. 

#### Installation
1. Extract the zip file to `Ghidra/Extensions`
2. Start Ghidra
3. Drag and drop PlayStation 4 binary into Ghidra (such as a game eboot)
4. Select PlayStation 4 ELF in the Format field
5. Press OK
6. ??
7. Profit.

#### Common Issues
~ If you are missing the `ps4database.xml` file, then the option to load a PlayStation 4 ELF will not show up.
~ Make sure your ELF is decrypted.
~ Make sure your ELF does not have the Sony header that is in encrypted ELF files.

#### TODO
~ I want to add a lot of features. Want to help? Please open an issue with an idea or submit a pull request!
~ Use StructConverter and show Sony and ELF header structures
~ Change region name from RAM to something else?
~ Make it so that imports are valid code, so it doesn't mess with decompiler

#### Credits
Major credits to xerpi for his Vita script, aerosoul94 for his dynlib project and database format, and Adubbz for his Switch loader. I was lazy to learn everything about Ghidra from scratch!
