# F2Amapper
This is python script that will extract the functions call in all used DLL in an executable and then provide a mapping of those functions to the attack classes defined and curated malapi.io.


#Current Features
-- Read Windows portable Executable files
-- Extract all the functions call from all the used DLLs
-- Map those functions call into attack class as per malapi.io classification
-- Show the results

#Planned features
-- 1. Making reading PE files and extracting function robust (to handle more complex crafted files)
-- 2. Provide mapping in more meaningful ways (Graphic representation and linking with the functions documents as in malapi.io)
-- 3. Providing saving the mapping output in different format like, csv, json, html, and other format used for security reports
-- 4. Adding multi-files/ folders scan support
-- 5. Adding more class of attack like VM-detection etc.
-- 6. Making mapping safe, and faster
-- 7. Creating pipeline to update the attack classes with update at malapi.io

# External python modules required
- pefile
- malapi.io Thanks to @mrd0x
