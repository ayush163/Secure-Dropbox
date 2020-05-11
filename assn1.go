package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096  //Do not modify this variable 

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution 
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username string
	PrK userlib.PrivateKey
	SyK []byte
	PassH []uint8
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileDir struct{
	Filename []byte
	InodeLoc []uint8
	K1 []uint8
}

type inode struct{
	Add []byte
	K3 []byte
	Ctr int
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	
	// Stores the location of the file to be shared between the sender and the receiver
	Sharing_location []uint8
	// Stores the symmetric key used to encrypt the sharing data structure
	Sym_key []byte
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length 
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (ud *User) StoreFile(filename string, data []byte) (err error) {

	var data1 = make([]byte, len(data))
	copy(data1, data)

	if len(data1)%configBlockSize != 0 {	    
        	err = errors.New("Invalid size of data")
		return
	}
	fdir := make(map[string]FileDir)
	flmac := userlib.NewHMAC(ud.PassH)
	flmac.Write([]byte(ud.Username))
	floc := flmac.Sum(nil)// File location HMAC(username)
	filedir, ok := userlib.DatastoreGet(string(floc))
	
	if !ok {
		return
	}
	fmac := filedir[:32]
	if len(fmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[32:]
	h2 := userlib.NewHMAC(ud.SyK)
	h2.Write(append(filedir,floc...))
	
	if !userlib.Equal(h2.Sum(nil), fmac) {
		
		err = errors.New("Corrupted Data")
		return
	}
	
	iv := filedir[:16]
	if len(iv)!=16{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[16:]
	cfdir := userlib.CFBDecrypter(ud.SyK, iv)
	cfdir.XORKeyStream(filedir, filedir)	//Decrypting File Directory
	err = json.Unmarshal(filedir, &fdir)
	
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}
	
	/*if _, ok := fdir[filename]; ok {

    	
	}*/
	k1 := userlib.Argon2Key(ud.PassH, userlib.RandomBytes(16),16)
    
	fsha := userlib.NewSHA256()
	fsha.Write([]byte(filename))
	filesha := fsha.Sum(nil)		//SHA256(filename)
	
	sha := userlib.NewSHA256()
	sha.Write(append([]byte(ud.Username), filesha...))
	mloc := sha.Sum(nil)		// Meta-Data location SHA256(username + SHA256(filename))
		
	fdir[filename] = FileDir{filesha, mloc, k1}
	mfdir, err2 := json.Marshal(fdir)
	
	if err2!=nil {
		return
	}
	
	ivf := userlib.RandomBytes(16)
	cfdir = userlib.CFBEncrypter(ud.SyK, ivf)
	cfdir.XORKeyStream(mfdir, mfdir)	//Encrypting File Directory
	
	mfdir = append(ivf, mfdir...)
	fmac1 := userlib.NewHMAC(ud.SyK)
	fmac1.Write(append(mfdir, floc...))
	filemac := fmac1.Sum(nil)			// HMAC(encrypted file directory + location)
	mfdir = append(filemac,mfdir...)
	userlib.DatastoreSet(string(floc), []byte(string(mfdir)))	//Storing encrypted file directory along with HMAC.
	
	var i1 []inode
	no_direct := (configBlockSize/(2*52))
	no_single := no_direct / 2
	no_double := no_single
	
	i:=0
	// i_Ctr := 0
	no_block := (len(data1)/configBlockSize)
	// println(no_block)
	singleflag := 0
	doubleflag := 0
	var i2 []inode;
	var i3 []inode;
	for no_block>0 {

		no_block--
		if i<no_direct {

			hash1 := userlib.NewSHA256()
			hash1.Write(append(mloc, append(filesha, []byte(string(i))...)...))
			dloc := hash1.Sum(nil)
			
			dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
			i1 = append(i1, inode{dloc, dkey, -1})
			
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data1 := userlib.CFBEncrypter(dkey, div)
			encrypt_data1.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey)
			dmac.Write(append(d1,dloc...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc),d1)
			i++
		} else if i< no_direct+no_single {

			if singleflag == 0 {
			
				singleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(mloc, append(filesha, []byte(string(i))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i1 = append(i1, inode{dloc, dkey, 0})
			}
			hash2 := userlib.NewSHA256()
			hash2.Write(append(i1[i].Add, append(filesha, []byte(string(i1[i].Ctr))...)...))
			i1[i].Ctr++
			dloc2 := hash2.Sum(nil)

			dkey2 := userlib.Argon2Key(i1[i].Add, userlib.RandomBytes(16),16)
			i2 = append(i2, inode{dloc2, dkey2, -1})
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data := userlib.CFBEncrypter(dkey2, div)
			encrypt_data.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey2)
			dmac.Write(append(d1,dloc2...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc2),d1)

			if no_block==0 || i1[i].Ctr==(configBlockSize/52) {

				mi2, err4 := json.Marshal(i2)
				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)//Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i1[i].K3)
				mmac.Write(append(mi2, i1[i].Add...))
				i2mac := mmac.Sum(nil)// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))//Storing encrypted file directory along with HMAC.

				i2 = nil
				
				i++;
				singleflag=0
			}
		} else if i < no_direct + no_single + no_double {
		// print("in double indirect\t")
			if doubleflag == 0 {
				
				doubleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(mloc, append(filesha, []byte(string(i))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i1 = append(i1, inode{dloc, dkey, 0})
			}
			
			if singleflag == 0 {
			
				singleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(i1[i].Add, append(filesha, []byte(string(i1[i].Ctr))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i2 = append(i2, inode{dloc, dkey, 0})
			}
			hash2 := userlib.NewSHA256()
			hash2.Write(append(i2[i1[i].Ctr].Add, append(filesha, []byte(string(i2[i1[i].Ctr].Ctr))...)...))
			i2[i].Ctr++
			dloc2 := hash2.Sum(nil)
			
			dkey2 := userlib.Argon2Key(i2[i1[i].Ctr].Add, userlib.RandomBytes(16),16)
			i3 = append(i3, inode{dloc2, dkey2, -1})
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data := userlib.CFBEncrypter(dkey2, div)
			encrypt_data.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey2)
			dmac.Write(append(d1,dloc2...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc2),d1)
			
			if no_block==0 || i2[i1[i].Ctr].Ctr==(configBlockSize/52) {
				
				mi2, err4 := json.Marshal(i3)
				
				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i2[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)	// Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i2[i].K3)
				mmac.Write(append(mi2, i2[i].Add...))
				i2mac := mmac.Sum(nil)			// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i2[i].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

				i3 = nil
				if i2[i1[i].Ctr].Ctr==(configBlockSize/52) {
					i1[i].Ctr++;
				}
				singleflag=0
			}
			
			if no_block==0 || i1[i].Ctr==(configBlockSize/52) {

				mi2, err4 := json.Marshal(i2)

				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)		//Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i1[i].K3)
				mmac.Write(append(mi2, i1[i].Add...))
				i2mac := mmac.Sum(nil)				// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

				i2 = nil
				if i1[i].Ctr==(configBlockSize/52) {
					i++;
			    }
				doubleflag=0
			}	
		}
	}
	// println()
	mi2, err4 := json.Marshal(i1)
	
	if err4!=nil {
	
		return
	}
	
	mivf := userlib.RandomBytes(16)
	mcfdir := userlib.CFBEncrypter(k1, mivf)
	mcfdir.XORKeyStream(mi2, mi2)			//Encrypting File Directory
	
	mi2 = append(mivf, mi2...)
	mmac := userlib.NewHMAC(k1)
	mmac.Write(append(mi2, mloc...))
	i2mac := mmac.Sum(nil)					// HMAC(encrypted file directory + location)
	mi2 = append(i2mac,mi2...)
	userlib.DatastoreSet(string(mloc), []byte(string(mi2)))		//Storing encrypted file directory along with HMAC.	
	return
}


//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var data1 = make([]byte, len(data))
	copy(data1, data)

	if len(data1)%configBlockSize != 0 {	    
        	err = errors.New("Invalid size of data")
		return
	}

	fdir := make(map[string]FileDir)
    flmac := userlib.NewHMAC(userdata.PassH)
    flmac.Write([]byte(userdata.Username))
	floc := flmac.Sum(nil)// File location HMAC(username)
	filedir, ok := userlib.DatastoreGet(string(floc))
	
	if !ok {
		err = errors.New("Failed to load file directory")
		return
	}
	fmac := filedir[:32]
	if len(fmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[32:]
	h2 := userlib.NewHMAC(userdata.SyK)
	h2.Write(append(filedir,floc...))
	
	if !userlib.Equal(h2.Sum(nil), fmac) {
		
		err = errors.New("Corrupted Data")
		return
	}
	
	iv := filedir[:16]
	if len(iv)!=16{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[16:]
	cfdir := userlib.CFBDecrypter(userdata.SyK, iv)
	cfdir.XORKeyStream(filedir, filedir)	//Decrypting File Directory
	err = json.Unmarshal(filedir, &fdir)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}

	if fdir[filename].K1 == nil {
		err = errors.New(strings.ToTitle("This is an error"))
		return
	}
	
	ind, ok := userlib.DatastoreGet(string(fdir[filename].InodeLoc))
	if !ok {
		err = errors.New("Failed to load from Data Store")
		return
	}

	imac := ind[:32]
	if len(imac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	ind = ind[32:]
	
	ght := userlib.NewHMAC(fdir[filename].K1)
	ght.Write(append(ind, fdir[filename].InodeLoc...))
	genimac := ght.Sum(nil)

	if !(userlib.Equal(imac, genimac)) {
		err = errors.New("HMAC did not match...File corrupted \n")
		return
	}

	iv = ind[:16]
	if len(iv)!=16{
		err = errors.New("HMAC changed")
		return
	}
	ind = ind[16:]

	cfdir = userlib.CFBDecrypter(fdir[filename].K1, iv)
	cfdir.XORKeyStream(ind, ind)	//Decrypting File Directory
	var i1 []inode
	err = json.Unmarshal(ind, &i1)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}
	
	no_direct := (configBlockSize/(2*52))
	no_single := no_direct / 2
	no_double := no_single
	
	i:=0
	
	
	singleflag := 0
	doubleflag := 0
	var i2 []inode;
	var i3 []inode;
	no_block := (configBlockSize/52)
	len_i1 := len(i1)
	i = len_i1 - 1
	ss := 0
	dd:=0
	// i_Ctr := 0
	if i < no_direct {
		i++
	} else if i < no_direct + no_single {
		if i1[i].Ctr == no_block {
			i++
		} else {
			singleflag = 1
			ss = 1
		}
	} else {
		if i1[i].Ctr == no_block {
			i++;
		} else {
			doubleflag = 1
			dd=1
		}
	}

	no_block = (len(data1)/configBlockSize)
	for no_block>0 {

		no_block--
		if i < no_direct {

			hash1 := userlib.NewSHA256()
			hash1.Write(append(fdir[filename].InodeLoc, append(fdir[filename].Filename, []byte(string(i))...)...))
			dloc := hash1.Sum(nil)
			
			dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
			i1 = append(i1, inode{dloc, dkey, -1})
			
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data := userlib.CFBEncrypter(dkey, div)
			encrypt_data.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey)
			dmac.Write(append(d1,dloc...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc),d1)
			i++
		} else if i< no_direct+no_single {
		
			if singleflag == 0 {
			
				singleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(fdir[filename].InodeLoc, append(fdir[filename].Filename, []byte(string(i))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i1 = append(i1, inode{dloc, dkey, 0})
			
			} else if ss == 1 {
				
				ss=0
				d, error5 := userlib.DatastoreGet(string(i1[i].Add))
				if !error5 {
					err = errors.New("Failed to load from Data Store")
					return
				}

				dmac := d[:32]
				if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
				d = d[32:]
				
				ght1 := userlib.NewHMAC(i1[i].K3)
				ght1.Write(append(d, i1[i].Add...))
				gendmac := ght1.Sum(nil)

				if !(userlib.Equal(dmac, gendmac)) {
					err = errors.New("HMAC did not match...File corrupted \n")
					return
				}

				div := d[:16]
				if len(div)!=16{
		err = errors.New("HMAC changed")
		return
	}
				d = d[16:]

				dfdir := userlib.CFBDecrypter(i1[i].K3, div)
				dfdir.XORKeyStream(d, d)

				err = json.Unmarshal(d, &i2)
				if err != nil {
					
					err = errors.New("Unmarshalling failed")
					return
				}
			}
			hash2 := userlib.NewSHA256()
			hash2.Write(append(i1[i].Add, append(fdir[filename].InodeLoc, []byte(string(i1[i].Ctr))...)...))
			i1[i].Ctr++
			dloc2 := hash2.Sum(nil)

			dkey2 := userlib.Argon2Key(i1[i].Add, userlib.RandomBytes(16),16)
			i2 = append(i2, inode{dloc2, dkey2, -1})
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data := userlib.CFBEncrypter(dkey2, div)
			encrypt_data.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey2)
			dmac.Write(append(d1,dloc2...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc2),d1)
			
			if no_block==0 || i1[i].Ctr==(configBlockSize/52) {

				mi2, err4 := json.Marshal(i2)
				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)//Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i1[i].K3)
				mmac.Write(append(mi2, i1[i].Add...))
				i2mac := mmac.Sum(nil)// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))//Storing encrypted file directory along with HMAC.

				i2 = nil
				if i1[i].Ctr==(configBlockSize/52){
					i++;
				}
				singleflag=0
			}
		} else if i < no_direct + no_single + no_double {
		
			if doubleflag == 0 {
				
				doubleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(fdir[filename].Filename, append(fdir[filename].Filename, []byte(string(i))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i1 = append(i1, inode{dloc, dkey, 0})
			
			} else if dd == 1{
				dd=0

				d, error5 := userlib.DatastoreGet(string(i1[i].Add))
				if !error5 {
					err = errors.New("Failed to load from Data Store")
					return
				}

				dmac := d[:32]
				if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
				d = d[32:]
				
				ght1 := userlib.NewHMAC(i1[i].K3)
				ght1.Write(append(d, i1[i].Add...))
				gendmac := ght1.Sum(nil)

				if !(userlib.Equal(dmac, gendmac)) {
					err = errors.New("HMAC did not match...File corrupted \n")
					return
				}

				div := d[:16]
				if len(div)!=16{
		err = errors.New("HMAC changed")
		return
	}
				d = d[16:]

				dfdir := userlib.CFBDecrypter(i1[i].K3, div)
				dfdir.XORKeyStream(d, d)

				err = json.Unmarshal(d, &i2)
				if err != nil {
					
					err = errors.New("Unmarshalling failed")
					return
				}

				// i_Ctr = len(i2) - 1
				if i2[i1[i].Ctr].Ctr < (configBlockSize/52){
					singleflag=1
					ss=1
				}

			}
			
			if singleflag == 0 {
			
				singleflag=1
				hash1 := userlib.NewSHA256()
				hash1.Write(append(i2[i1[i].Ctr].Add, append(fdir[filename].Filename, []byte(string(i1[i1[i].Ctr].Ctr))...)...))
				dloc := hash1.Sum(nil)
				
				dkey := userlib.Argon2Key(dloc, userlib.RandomBytes(16),16)
				i2 = append(i2, inode{dloc, dkey, 0})
			} else if (ss==1) {
				ss=0
				d, error5 := userlib.DatastoreGet(string(i2[i1[i].Ctr].Add))
				if !error5 {
					err = errors.New("Failed to load from Data Store")
					return
				}

				dmac := d[:32]
				if len(dmac)!=32{
					err = errors.New("HMAC changed")
					return
				}	
				d = d[32:]
				
				ght1 := userlib.NewHMAC(i2[i1[i].Ctr].K3)
				ght1.Write(append(d, i2[i1[i].Ctr].Add...))
				gendmac := ght1.Sum(nil)

				if !(userlib.Equal(dmac, gendmac)) {
					err = errors.New("HMAC did not match...File corrupted \n")
					return
				}

				div := d[:16]
				if len(div)!=16{
					err = errors.New("HMAC changed")
					return
				}
				d = d[16:]

				dfdir := userlib.CFBDecrypter(i2[i1[i].Ctr].K3, div)
				dfdir.XORKeyStream(d, d)

				err = json.Unmarshal(d, &i3)
				if err != nil {
					
					err = errors.New("Unmarshalling failed")
					return
				}
			
			}
			hash2 := userlib.NewSHA256()
			hash2.Write(append(i2[i1[i].Ctr].Add, append(fdir[filename].Filename, []byte(string(i2[i1[i].Ctr].Ctr))...)...))
			i2[i1[i].Ctr].Ctr++
			dloc2 := hash2.Sum(nil)
			
			dkey2 := userlib.Argon2Key(i2[i1[i].Ctr].Add, userlib.RandomBytes(16),16)
			i3 = append(i3, inode{dloc2, dkey2, -1})
			d1 := data1[:configBlockSize]
			data1 = data1[configBlockSize:]
			div := userlib.RandomBytes(16)
			encrypt_data := userlib.CFBEncrypter(dkey2, div)
			encrypt_data.XORKeyStream(d1, d1)
			d1 = append(div, d1...)
			dmac := userlib.NewHMAC(dkey2)
			dmac.Write(append(d1,dloc2...))
			data_hmac := dmac.Sum(nil)
			d1 = append(data_hmac, d1...)
			userlib.DatastoreSet(string(dloc2),d1)
			
			if no_block==0 || i2[i1[i].Ctr].Ctr==(configBlockSize/52) {
				
				mi2, err4 := json.Marshal(i3)
				
				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i2[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)	// Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i2[i].K3)
				mmac.Write(append(mi2, i2[i].Add...))
				i2mac := mmac.Sum(nil)			// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i2[i].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

				i3 = nil
				if i2[i1[i].Ctr].Ctr==(configBlockSize/52) {
					i1[i].Ctr++;
				}
				singleflag=0
			}
			
			if no_block==0 || i1[i].Ctr==(configBlockSize/52) {

				mi2, err4 := json.Marshal(i2)

				if err4!=nil {
					return
				}
				
				mivf := userlib.RandomBytes(16)
				mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
				mcfdir.XORKeyStream(mi2, mi2)		//Encrypting File Directory
				
				mi2 = append(mivf, mi2...)
				mmac := userlib.NewHMAC(i1[i].K3)
				mmac.Write(append(mi2, i1[i].Add...))
				i2mac := mmac.Sum(nil)				// HMAC(encrypted file directory + location)
				mi2 = append(i2mac,mi2...)
				userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

				i2 = nil
				if i1[i].Ctr==(configBlockSize/52) {
					i++;
				}
				doubleflag=0
			}	
		}
	}
	
	mi2, err4 := json.Marshal(i1)
	
	if err4!=nil {
	
		return
	}
	
	mivf := userlib.RandomBytes(16)
	mcfdir := userlib.CFBEncrypter(fdir[filename].K1, mivf)
	mcfdir.XORKeyStream(mi2, mi2)			//Encrypting File Directory
	
	mi2 = append(mivf, mi2...)
	mmac := userlib.NewHMAC(fdir[filename].K1)
	mmac.Write(append(mi2, fdir[filename].InodeLoc...))
	i2mac := mmac.Sum(nil)					// HMAC(encrypted file directory + location)
	mi2 = append(i2mac,mi2...)
	userlib.DatastoreSet(string(fdir[filename].InodeLoc), []byte(string(mi2)))	

	return err
}


// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
// 
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	if offset < 0{
		err = errors.New("Invalid offset")
		return
	}
	fdir := make(map[string]FileDir)
    flmac := userlib.NewHMAC(userdata.PassH)
    flmac.Write([]byte(userdata.Username))
	floc := flmac.Sum(nil)// File location HMAC(username)
	filedir, ok := userlib.DatastoreGet(string(floc))
	
	if !ok {
		err = errors.New("Failed to load file directory")
		return
	}
	fmac := filedir[:32]
	if len(fmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[32:]
	h2 := userlib.NewHMAC(userdata.SyK)
	h2.Write(append(filedir,floc...))
	
	if !userlib.Equal(h2.Sum(nil), fmac) {
		
		err = errors.New("Corrupted Data")
		return
	}
	
	iv := filedir[:16]
	if len(iv)!=16{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[16:]
	cfdir := userlib.CFBDecrypter(userdata.SyK, iv)
	cfdir.XORKeyStream(filedir, filedir)	//Decrypting File Directory
	err = json.Unmarshal(filedir, &fdir)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}

	if fdir[filename].K1 == nil {
		err = errors.New(strings.ToTitle("This is an error"))
		return
	}
	
	ind1, ok := userlib.DatastoreGet(string(fdir[filename].InodeLoc))
	if !ok {
		err = errors.New("Failed to load from Data Store")
		return
	}

	imac := ind1[:32]
	if len(imac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	ind1 = ind1[32:]
	
	ght := userlib.NewHMAC(fdir[filename].K1)
	ght.Write(append(ind1, fdir[filename].InodeLoc...))
	genimac := ght.Sum(nil)

	if !(userlib.Equal(imac, genimac)) {
		err = errors.New("HMAC did not match...File corrupted \n")
		return
	}

	iv = ind1[:16]
	if len(iv)!=16{
		err = errors.New("HMAC changed")
		return
	}
	ind1 = ind1[16:]

	cfdir = userlib.CFBDecrypter(fdir[filename].K1, iv)
	cfdir.XORKeyStream(ind1, ind1)	//Decrypting File Directory
	var i1 []inode
	err = json.Unmarshal(ind1, &i1)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}
	
	no_direct := (configBlockSize/(2*52))
	no_single := no_direct / 2
	no_double := no_single
	
	i:=0
	no_block := (configBlockSize/52)
	// print(no_direct, "\t")
//	singleflag := 0
//	doubleflag := 0
//	var i2 []inode;
//	var i3 []inode;
	if offset < no_direct && offset < len(i1){

		d, error5 := userlib.DatastoreGet(string(i1[offset].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac := d[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
		}
		d = d[32:]
		
		ght1 := userlib.NewHMAC(i1[offset].K3)
		ght1.Write(append(d, i1[offset].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div := d[:16]
		if len(div)!=16{
		err = errors.New("HMAC changed")
		return
		}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i1[offset].K3, div)
		dfdir.XORKeyStream(d, d)	//Decrypting File Directory

		data = append(data, d...)


	} else if offset < no_direct + (no_single * no_block){

		offset = offset - no_direct
		i = no_direct
		for offset >= no_block {
			 offset = offset - no_block
			 i++
		}
		if i>=len(i1) {
			err = errors.New("Invalid offset")
			return
		}
		d, error5 := userlib.DatastoreGet(string(i1[i].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}
		dmac := d[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
		}
		d = d[32:]
		ght1 := userlib.NewHMAC(i1[i].K3)
		ght1.Write(append(d, i1[i].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}
		div := d[:16]
		if len(div)!=16{
		err = errors.New("HMAC changed")
		return
		}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i1[i].K3, div)
		dfdir.XORKeyStream(d, d)

		var i2[] inode

		err = json.Unmarshal(d, &i2)
		if err != nil {
			
			err = errors.New("Unmarshalling failed")
			return
		}
		if offset>=len(i2) {
			err = errors.New("Invalid offset")
			return
		}
		d, error5 = userlib.DatastoreGet(string(i2[offset].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac = d[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
		}
		d = d[32:]
		
		ght1 = userlib.NewHMAC(i2[offset].K3)
		ght1.Write(append(d, i2[offset].Add...))
		gendmac = ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div = d[:16]
		if len(div)!=16{
		err = errors.New("HMAC changed")
		return
	}
		d = d[16:]
		dfdir = userlib.CFBDecrypter(i2[offset].K3, div)
		dfdir.XORKeyStream(d, d)	//Decrypting File Directory
		data = append(data, d...)

	} else if offset < no_direct + (no_single * no_block) + (no_double * no_block * no_block) {

		offset = offset - no_direct - (no_single * no_block)

		i := no_direct + no_single

		for offset >= (no_block * no_block) {
			offset = offset - ( no_block * no_block)
			i++
		}
		if i>=len(i1) {
			err = errors.New("Invalid offset")
			return
		}
		d, error5 := userlib.DatastoreGet(string(i1[i].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac := d[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
		d = d[32:]
		
		ght1 := userlib.NewHMAC(i1[i].K3)
		ght1.Write(append(d, i1[i].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div := d[:16]
		if len(div)!=16{
		err = errors.New("HMAC changed")
		return
	}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i1[i].K3, div)
		dfdir.XORKeyStream(d, d)
		var i2[] inode

		err = json.Unmarshal(d, &i2)
		if err != nil {
			
			err = errors.New("Unmarshalling failed")
			return
		}

		ii := 0
		for offset >= no_block {
			 offset = offset - no_block
			 ii++
		}
		if ii>=len(i2) {
			err = errors.New("Invalid offset")
			return
		}
		d2 , error7 := userlib.DatastoreGet(string(i2[ii].Add))
		if !error7 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac = d2[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
		d2 = d2[32:]
		
		ght1 = userlib.NewHMAC(i2[ii].K3)
		ght1.Write(append(d2, i2[ii].Add...))
		gendmac = ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div = d2[:16]
		if len(div)!=16{
		err = errors.New("HMAC changed")
		return
	}
		d2 = d2[16:]

		dfdir = userlib.CFBDecrypter(i2[ii].K3, div)
		dfdir.XORKeyStream(d2, d2)

		var i3[] inode

		err = json.Unmarshal(d2, &i3)
		if err != nil {
			
			err = errors.New("Unmarshalling failed")
			return
		}
		if offset>=len(i3) {
			err = errors.New("Invalid offset")
			return
		}
		d3, error8 := userlib.DatastoreGet(string(i3[offset].Add))
		if !error8 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac = d3[:32]
		if len(dmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
		d3 = d3[32:]
		
		ght1 = userlib.NewHMAC(i3[offset].K3)
		ght1.Write(append(d3, i3[offset].Add...))
		gendmac = ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div = d3[:16]
		if len(div)!=16{
		err = errors.New("IV changed")
		return
	}
		d3 = d3[16:]

		dfdir = userlib.CFBDecrypter(i3[offset].K3, div)
		dfdir.XORKeyStream(d3, d3)	//Decrypting File Directory

		data = append(data, d3...)

	}
	return
}



// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	recipientPubKey, validity1 := userlib.KeystoreGet(recipient)
	if validity1 == false {
		// Checks whether the "recipient" entered is valid or not
		err = errors.New("Invalid recipient.")
		return
	}
	

	FileDirectory := make(map[string]FileDir)
	
	flmac := userlib.NewHMAC(userdata.PassH)
	flmac.Write([]byte(userdata.Username))
	fileDirLoc := flmac.Sum(nil)
	
	fileDir, ok := userlib.DatastoreGet(string(fileDirLoc))
	if ok == false {
		err = errors.New("DataStore get failed")
	}
	
	fmac := fileDir[:32]
	if len(fmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	fileDir = fileDir[32:]
	h2 := userlib.NewHMAC(userdata.SyK)
	h2.Write(append(fileDir, fileDirLoc...))

	if !userlib.Equal(h2.Sum(nil), fmac) {
		err = errors.New("Corrupted Data")
		return
	}

	iv := fileDir[:16]
	if len(iv)!=16{
		err = errors.New("IV changed")
		return
	}
	fileDir = fileDir[16:]

	crypt := userlib.CFBDecrypter(userdata.SyK, iv) 	//Decrypt the file directory
	crypt.XORKeyStream(fileDir, fileDir)            	// get the decrrypted file directory in json format
	err = json.Unmarshal(fileDir, &FileDirectory)  
	if err != nil {
		err = errors.New("Unmarshalling Failed")
		return
	}
	
	filedata, ok := FileDirectory[filename]
	if !ok {
		err = errors.New("No such file exists")
		return
	}
	
	var sharingData sharingRecord
	

	sharingData.Sharing_location = filedata.InodeLoc
	sharingData.Sym_key = filedata.K1

	sD, erry := json.Marshal(sharingData)
	if erry != nil {
		err = errors.New("Marshalling Failed")
		return
	}
	// Encrypt sharingData using recipient's public key
	Sign, err3 := userlib.RSASign(&userdata.PrK, sD)
	if err3 != nil {
		err = errors.New("RSA Signing Failed")
		return
	}

	Data, err4 := userlib.RSAEncrypt(&recipientPubKey, sD, []byte(nil))
	if err4 != nil {
		err = errors.New("Encrypt Fail : Failed to Encrypt Sharing object")
		return
	}

	sD = []byte(append(Sign, Data...))
	

	sha1 := userlib.NewSHA256()
	sha1.Write([]byte(userdata.Username))
	sha_ := sha1.Sum(nil)

	sha2 := userlib.NewSHA256()
	sha2.Write(sha_)
	Fsha := sha2.Sum(nil)

	// this key will be used to generate the HMAC(encrypted sharing struct + SHA(username + filename))
	ks := userlib.Argon2Key(Fsha, []byte(userdata.Username), 16)


	sha3 := userlib.NewSHA256()
	
	sha3.Write(append([]byte(userdata.Username + recipient), filedata.Filename...))
	shLoc := sha2.Sum(nil)
	//println("sharing location is : ", string(shLoc))
	shmac := userlib.NewHMAC(ks)
	shmac.Write(append(sD, shLoc...))
	finalMac := shmac.Sum(nil)

	shhh := userlib.NewSHA256()
	shhh.Write([]byte(recipient + userdata.Username))
	sd_mac_loc := shhh.Sum(nil)
	userlib.DatastoreSet(string(sd_mac_loc),finalMac)
	//sD = append(finalMac, sD...)
	userlib.DatastoreSet(string(shLoc), []byte(string(sD)))

	// Encrypt sharingData using recipient's public key
	Sign1, err5 := userlib.RSASign(&userdata.PrK, shLoc)
	if err5 != nil {
		err = errors.New("RSA Signing Failed")
		return
	}
	Data1, err6 := userlib.RSAEncrypt(&recipientPubKey, shLoc, []byte(nil))
	if err6 != nil {
		err = errors.New("Encrypt Fail : Failed to Encrypt Sharing object")
		return
	}
	
	msgid = string(append(Sign1, Data1...))
	return
}




// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
//println(sender)
	senderPubKey, ok := userlib.KeystoreGet(sender)
/*	x := userlib.KeystoreGetMap()
	// println(string(senderPubKey))
	println("the keystore map is: ")
	if x[sender] == senderPubKey {
		print("key is getting stored")
	}*/
	// println(string(senderPubKey))
	if ok == false {
		// Checks whether the "recipient" entered is valid or not
		return errors.New("Invalid sender")
	}

	
	msgb := []byte(msgid)
	msgSharing, err1 := userlib.RSADecrypt(&userdata.PrK, msgb[256:], nil)
	if err1 != nil {
		return errors.New("RSA Decrypt Failed")
	}
	
	errx := userlib.RSAVerify(&senderPubKey, msgSharing, msgb[:256])
	if errx != nil {
		return errors.New("RSA verification failed")
	}
	
	shdata, ok := userlib.DatastoreGet(string(msgSharing))
	//println("in receive file: ", string(msgSharing))
	if !ok {
		return errors.New("Failed to load from DS")
	}
	
	/*smac := shdata[:32]
	if len(smac)!=32{
		err := errors.New("HMAC changed")
		return err
	}
	shdata = shdata[32:]
	*/

	sha1 := userlib.NewSHA256()
	sha1.Write([]byte(sender))
	sha_ := sha1.Sum(nil)

	sha2 := userlib.NewSHA256()
	sha2.Write(sha_)
	Fsha := sha2.Sum(nil)

	// this key will be used to generate the HMAC(encrypted sharing struct + SHA(username + filename))
	ks := userlib.Argon2Key(Fsha, []byte(sender), 16)
	shmac := userlib.NewHMAC(ks)
	shmac.Write(append(shdata, msgSharing...))
	finalMac := shmac.Sum(nil)
	
	shhh := userlib.NewSHA256()
	shhh.Write([]byte(userdata.Username + sender))
	sd_mac_loc := shhh.Sum(nil)
	smac, ok := userlib.DatastoreGet(string(sd_mac_loc))
	if !ok{
		return errors.New("Failed to load HMAC")
	}

	if !userlib.Equal(finalMac, smac){
		return errors.New("MAC did not match")
	}
	
	shared_ds, err4 := userlib.RSADecrypt(&userdata.PrK, shdata[256:], nil)
	if err4 != nil {
		return errors.New("RSA Decrypt Failed")
	}
	err5 := userlib.RSAVerify(&senderPubKey, shared_ds, shdata[:256])
	if err5 != nil {
		return errors.New("RSA verification failed")
	}
	
	var sD sharingRecord
	err6 := json.Unmarshal(shared_ds, &sD)
	if err6 != nil{
		return errors.New("Failed to unmarshal")
	}
	
	FileDirectory := make(map[string]FileDir)
	
	flmac := userlib.NewHMAC(userdata.PassH)
	flmac.Write([]byte(userdata.Username))
	fileDirLoc := flmac.Sum(nil)
	
	fileDir, ok := userlib.DatastoreGet(string(fileDirLoc))
	if !ok {
		return errors.New("DataStore get failed")
	}
	
	fmac := fileDir[:32]
	if len(fmac)!=32{
		err := errors.New("HMAC changed")
		return err
	}
	fileDir = fileDir[32:]
	h2 := userlib.NewHMAC(userdata.SyK)
	h2.Write(append(fileDir, fileDirLoc...))

	if !userlib.Equal(h2.Sum(nil), fmac) {
		return errors.New("Corrupted Data")
	}

	iv := fileDir[:16]
	if len(iv)!=16{
		err := errors.New("IV changed")
		return err
	}
	fileDir = fileDir[16:]

	crypt := userlib.CFBDecrypter(userdata.SyK, iv) 	//Decrypt the file directory
	crypt.XORKeyStream(fileDir, fileDir)            	// get the decrypted file directory in json format
	err8 := json.Unmarshal(fileDir, &FileDirectory)  
	if err8 != nil {
		err8 = errors.New("Unmarshalling Failed")
		return err8
	}

	/*if userdata.Username == sender {
		return errors.New("User cannot share file with himself")
	}*/


	fsha := userlib.NewSHA256()
	fsha.Write([]byte(filename))
	filesha := fsha.Sum(nil)
	FileDirectory[filename] = FileDir{filesha, sD.Sharing_location, sD.Sym_key}

	mfdir, err2 := json.Marshal(FileDirectory)
	
	if err2!=nil {

		return errors.New("Failed to marshal")
	}
	ivf := userlib.RandomBytes(16)
	cfdir := userlib.CFBEncrypter(userdata.SyK, ivf)
	cfdir.XORKeyStream(mfdir, mfdir)	//Encrypting File Directory
	
	mfdir = append(ivf, mfdir...)
	fmac1 := userlib.NewHMAC(userdata.SyK)
	fmac1.Write(append(mfdir, fileDirLoc...))
	filemac := fmac1.Sum(nil)			// HMAC(encrypted file directory + location)
	mfdir = append(filemac,mfdir...)
	userlib.DatastoreSet(string(fileDirLoc), []byte(string(mfdir)))
	return nil
}



// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	fdir := make(map[string]FileDir)
    flmac := userlib.NewHMAC(userdata.PassH)
    flmac.Write([]byte(userdata.Username))
	floc := flmac.Sum(nil)// File location HMAC(username)
	filedir, ok := userlib.DatastoreGet(string(floc))
	
	if !ok {
		err = errors.New("Failed to load file directory")
		return
	}
	fmac := filedir[:32]
	if len(fmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	filedir = filedir[32:]
	h2 := userlib.NewHMAC(userdata.SyK)
	h2.Write(append(filedir,floc...))
	
	if !userlib.Equal(h2.Sum(nil), fmac) {
		
		err = errors.New("Corrupted Data")
		return
	}
	
	iv := filedir[:16]
	if len(iv)!=16{
		err = errors.New("IV changed")
		return
	}
	filedir = filedir[16:]
	cfdir := userlib.CFBDecrypter(userdata.SyK, iv)
	cfdir.XORKeyStream(filedir, filedir)	//Decrypting File Directory
	err = json.Unmarshal(filedir, &fdir)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}

	if fdir[filename].K1 == nil {
		err = errors.New(strings.ToTitle("This is an error"))
		return
	}
	
	ind, ok := userlib.DatastoreGet(string(fdir[filename].InodeLoc))
	userlib.DatastoreDelete(string(fdir[filename].InodeLoc))
	if !ok {
		err = errors.New("Failed to load from Data Store")
		return
	}

	imac := ind[:32]
	if len(imac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	ind = ind[32:]
	
	ght := userlib.NewHMAC(fdir[filename].K1)
	ght.Write(append(ind, fdir[filename].InodeLoc...))
	genimac := ght.Sum(nil)

	if !(userlib.Equal(imac, genimac)) {
		err = errors.New("HMAC did not match...File corrupted \n")
		return
	}

	iv = ind[:16]
	if len(iv)!=16{
		err = errors.New("IV changed")
		return
	}
	ind = ind[16:]

	cfdir = userlib.CFBDecrypter(fdir[filename].K1, iv)
	cfdir.XORKeyStream(ind, ind)	//Decrypting File Directory
	var i1 []inode
	err = json.Unmarshal(ind, &i1)
	if err != nil {
		
		err = errors.New("Unmarshalling failed")
		return
	}
	
	no_direct := (configBlockSize/(2*52))
	no_single := no_direct / 2
	no_double := no_single
	
	i:=0
	i_Ctr := 0
	i2_Ctr := 0
	
	singleflag := 0
	doubleflag := 0
	var i2 []inode;
	var i3 []inode;
	
	
	l := len(i1)	
	

		
	for i<l && i < no_direct {

		d, error5 := userlib.DatastoreGet(string(i1[i].Add))
		userlib.DatastoreDelete(string(i1[i].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac := d[:32]
		if len(dmac)!=32{
			err = errors.New("HMAC changed")
			return
		}
		d = d[32:]
		
		ght1 := userlib.NewHMAC(i1[i].K3)
		ght1.Write(append(d, i1[i].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div := d[:16]
		if len(div)!=16{
			err = errors.New("IV changed")
			return
		}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i1[i].K3, div)
		dfdir.XORKeyStream(d, d)	
		///////////////////////////////////////////////
		tt := userlib.NewSHA256()
		tt.Write(i1[i].Add)
		i1[i].Add = tt.Sum(nil)
		i1[i].K3 = userlib.Argon2Key(i1[i].Add, userlib.RandomBytes(16),16)


		div = userlib.RandomBytes(16)
		encrypt_data := userlib.CFBEncrypter(i1[i].K3, div)
		encrypt_data.XORKeyStream(d, d)
		d = append(div, d...)
		dmac1 := userlib.NewHMAC(i1[i].K3)
		dmac1.Write(append(d,i1[i].Add...))
		data_hmac := dmac1.Sum(nil)
		d = append(data_hmac, d...)
		userlib.DatastoreSet(string(i1[i].Add),d)
		i++
	} 
	for i<l && i< ( no_direct + no_single ) && i_Ctr < i1[i].Ctr{

		if singleflag == 0 {
		
			singleflag=1
			d, error5 := userlib.DatastoreGet(string(i1[i].Add))
			userlib.DatastoreDelete(string(i1[i].Add))
			if !error5 {
				err = errors.New("Failed to load from Data Store")
				return
			}

			dmac := d[:32]
			if len(dmac)!=32{
				err = errors.New("HMAC changed")
				return
			}
			d = d[32:]
			
			ght1 := userlib.NewHMAC(i1[i].K3)
			ght1.Write(append(d, i1[i].Add...))
			gendmac := ght1.Sum(nil)

			if !(userlib.Equal(dmac, gendmac)) {
				err = errors.New("HMAC did not match...File corrupted \n")
				return
			}

			div := d[:16]
			if len(div)!=16{
				err = errors.New("IV changed")
				return
			}
			d = d[16:]

			dfdir := userlib.CFBDecrypter(i1[i].K3, div)
			dfdir.XORKeyStream(d, d)

			err = json.Unmarshal(d, &i2)
			if err != nil {
				
				err = errors.New("Unmarshalling failed")
				return
			}
			/////////////////////////////
			i_Ctr = 0
			
		}

		d, error5 := userlib.DatastoreGet(string(i2[i_Ctr].Add))
		userlib.DatastoreDelete(string(i2[i_Ctr].Add))
			if !error5 {
				err = errors.New("Failed to load from Data Store")
				return
			}

		dmac := d[:32]
		if len(dmac)!=32{
			err = errors.New("HMAC changed")
			return
		}
		d = d[32:]
		
		ght1 := userlib.NewHMAC(i2[i_Ctr].K3)
		ght1.Write(append(d, i2[i_Ctr].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div := d[:16]
		if len(div)!=16{
			err = errors.New("IV changed")
			return
		}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i2[i_Ctr].K3, div)
		dfdir.XORKeyStream(d, d)	
		
		tt := userlib.NewSHA256()
		tt.Write(i2[i_Ctr].Add)
		i2[i_Ctr].Add = tt.Sum(nil)
		i2[i_Ctr].K3 = userlib.Argon2Key(i2[i_Ctr].Add, userlib.RandomBytes(16),16)


		div = userlib.RandomBytes(16)
		encrypt_data := userlib.CFBEncrypter(i2[i_Ctr].K3, div)
		encrypt_data.XORKeyStream(d, d)
		d = append(div, d...)
		dmac2 := userlib.NewHMAC(i2[i_Ctr].K3)
		dmac2.Write(append(d,i2[i_Ctr].Add...))
		data_hmac := dmac2.Sum(nil)
		d = append(data_hmac, d...)
		userlib.DatastoreSet(string(i2[i_Ctr].Add),d)
		////////////////////////////
		i_Ctr++
		
		if i1[i].Ctr == i_Ctr {

			mi2, err4 := json.Marshal(i2)
			if err4!=nil {
				return
			}
			tt1 := userlib.NewSHA256()
			tt1.Write(i1[i].Add)
			i1[i].Add = tt1.Sum(nil)
			i1[i].K3 = userlib.Argon2Key(i1[i].Add, userlib.RandomBytes(16),16)
			mivf := userlib.RandomBytes(16)
			mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
			mcfdir.XORKeyStream(mi2, mi2)//Encrypting File Directory
			
			mi2 = append(mivf, mi2...)
			mmac := userlib.NewHMAC(i1[i].K3)
			mmac.Write(append(mi2, i1[i].Add...))
			i2mac := mmac.Sum(nil)// HMAC(encrypted file directory + location)
			mi2 = append(i2mac,mi2...)
			userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))//Storing encrypted file directory along with HMAC.

			i2 = nil
			i++;
			singleflag=0
		}
	} 
	for i<l && i < no_direct + no_single + no_double && i_Ctr < i1[i].Ctr && i2_Ctr < i2[i_Ctr].Ctr {
	
		if doubleflag == 0 {
			
			doubleflag=1

			d, error5 := userlib.DatastoreGet(string(i1[i].Add))
			userlib.DatastoreDelete(string(i1[i].Add))
			if !error5 {
				err = errors.New("Failed to load from Data Store")
				return
			}

			dmac := d[:32]
			if len(dmac)!=32{
				err = errors.New("HMAC changed")
				return
			}
			d = d[32:]
			
			ght1 := userlib.NewHMAC(i1[i].K3)
			ght1.Write(append(d, i1[i].Add...))
			gendmac := ght1.Sum(nil)

			if !(userlib.Equal(dmac, gendmac)) {
				err = errors.New("HMAC did not match...File corrupted \n")
				return
			}

			div := d[:16]
			if len(div)!=16{
				err = errors.New("IV changed")
				return
			}
			d = d[16:]

			dfdir := userlib.CFBDecrypter(i1[i].K3, div)
			dfdir.XORKeyStream(d, d)

			err = json.Unmarshal(d, &i2)
			if err != nil {
				
				err = errors.New("Unmarshalling failed")
				return
			}
			/////////////////////////////
			i_Ctr = 0
			
		}
		
		if singleflag == 0 {
		
			singleflag=1

			d, error5 := userlib.DatastoreGet(string(i2[i_Ctr].Add))
			userlib.DatastoreDelete(string(i2[i_Ctr].Add))
			if !error5 {
				err = errors.New("Failed to load from Data Store")
				return
			}

			dmac := d[:32]
			if len(dmac)!=32{
				err = errors.New("HMAC changed")
				return
			}
			d = d[32:]
			
			ght1 := userlib.NewHMAC(i2[i_Ctr].K3)
			ght1.Write(append(d, i2[i_Ctr].Add...))
			gendmac := ght1.Sum(nil)

			if !(userlib.Equal(dmac, gendmac)) {
				err = errors.New("HMAC did not match...File corrupted \n")
				return
			}

			div := d[:16]
			if len(div)!=16{
				err = errors.New("IV changed")
				return
			}
			d = d[16:]

			dfdir := userlib.CFBDecrypter(i2[i_Ctr].K3, div)
			dfdir.XORKeyStream(d, d)

			err = json.Unmarshal(d, &i3)
			if err != nil {
				
				err = errors.New("Unmarshalling failed")
				return
			}
		
			i2_Ctr = 0
			
		}

		
		d, error5 := userlib.DatastoreGet(string(i3[i2_Ctr].Add))
		userlib.DatastoreDelete(string(i3[i2_Ctr].Add))
		if !error5 {
			err = errors.New("Failed to load from Data Store")
			return
		}

		dmac := d[:32]
		if len(dmac)!=32{
			err = errors.New("HMAC changed")
			return
		}	

		d = d[32:]
		
		ght1 := userlib.NewHMAC(i3[i2_Ctr].K3)
		ght1.Write(append(d, i3[i2_Ctr].Add...))
		gendmac := ght1.Sum(nil)

		if !(userlib.Equal(dmac, gendmac)) {
			err = errors.New("HMAC did not match...File corrupted \n")
			return
		}

		div := d[:16]
		if len(div)!=16{
			err = errors.New("IV changed")
			return
		}
		d = d[16:]

		dfdir := userlib.CFBDecrypter(i3[i2_Ctr].K3, div)
		dfdir.XORKeyStream(d, d)	
		
		tt := userlib.NewSHA256()
		tt.Write(i3[i2_Ctr].Add)
		i3[i2_Ctr].Add = tt.Sum(nil)
		i3[i2_Ctr].K3 = userlib.Argon2Key(i3[i2_Ctr].Add, userlib.RandomBytes(16),16)


		div = userlib.RandomBytes(16)
		encrypt_data := userlib.CFBEncrypter(i3[i2_Ctr].K3, div)
		encrypt_data.XORKeyStream(d, d)
		d = append(div, d...)
		dmac3 := userlib.NewHMAC(i3[i2_Ctr].K3)
		dmac3.Write(append(d,i3[i2_Ctr].Add...))
		data_hmac := dmac3.Sum(nil)
		d = append(data_hmac, d...)
		userlib.DatastoreSet(string(i3[i2_Ctr].Add),d)
		
		i2_Ctr++

		
		
		if i2_Ctr==i2[i_Ctr].Ctr {
			
			mi2, err4 := json.Marshal(i3)
			
			if err4!=nil {
				return
			}
			
			mivf := userlib.RandomBytes(16)
			tt1 := userlib.NewSHA256()
			tt1.Write(i2[i_Ctr].Add)
			i2[i_Ctr].Add = tt1.Sum(nil)
			i2[i_Ctr].K3 = userlib.Argon2Key(i2[i_Ctr].Add, userlib.RandomBytes(16),16)
			mcfdir := userlib.CFBEncrypter(i2[i_Ctr].K3, mivf)
			mcfdir.XORKeyStream(mi2, mi2)	// Encrypting File Directory
			
			mi2 = append(mivf, mi2...)
			mmac := userlib.NewHMAC(i2[i_Ctr].K3)
			mmac.Write(append(mi2, i2[i_Ctr].Add...))
			i2mac := mmac.Sum(nil)			// HMAC(encrypted file directory + location)
			mi2 = append(i2mac,mi2...)
			userlib.DatastoreSet(string(i2[i_Ctr].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

			i3 = nil
			i_Ctr++
			singleflag=0
		}
		
		if i_Ctr==i1[i].Ctr {

			mi2, err4 := json.Marshal(i2)

			if err4!=nil {
				return
			}
			tt1 := userlib.NewSHA256()
			tt1.Write(i1[i].Add)
			i1[i].Add= tt1.Sum(nil)
			i1[i].K3 = userlib.Argon2Key(i1[i].Add, userlib.RandomBytes(16),16)
			mivf := userlib.RandomBytes(16)
			mcfdir := userlib.CFBEncrypter(i1[i].K3, mivf)
			mcfdir.XORKeyStream(mi2, mi2)		//Encrypting File Directory
			
			mi2 = append(mivf, mi2...)
			mmac := userlib.NewHMAC(i1[i].K3)
			mmac.Write(append(mi2, i1[i].Add...))
			i2mac := mmac.Sum(nil)				// HMAC(encrypted file directory + location)
			mi2 = append(i2mac,mi2...)
			userlib.DatastoreSet(string(i1[i].Add), []byte(string(mi2)))	//Storing encrypted file directory along with HMAC.

			i2 = nil
			i++;
			doubleflag=0
		}	
	}
	
	
	mi2, err4 := json.Marshal(i1)
	
	if err4!=nil {
		err = errors.New("Error in Marshalling")
		return
	}
	var fn FileDir
	fn.Filename = fdir[filename].Filename
	fn.InodeLoc = fdir[filename].InodeLoc
	tt := userlib.NewSHA256()
	tt.Write(fdir[filename].InodeLoc)
	fn.InodeLoc = tt.Sum(nil)
	fn.K1 = userlib.Argon2Key(fn.InodeLoc, userlib.RandomBytes(16),16)
	fdir[filename] = fn
	mivf := userlib.RandomBytes(16)
	mcfdir := userlib.CFBEncrypter(fdir[filename].K1, mivf)
	mcfdir.XORKeyStream(mi2, mi2)			//Encrypting File Directory
	
	mi2 = append(mivf, mi2...) 
	mmac := userlib.NewHMAC(fdir[filename].K1)
	mmac.Write(append(mi2, fdir[filename].InodeLoc...)) 
	i2mac := mmac.Sum(nil)					// HMAC(encrypted file directory + location) mi2 =
	mi2=append(i2mac,mi2...)
	userlib.DatastoreSet(string(fdir[filename].InodeLoc),[]byte(string(mi2)))	


	mfdir, error3 := json.Marshal(fdir)
	if error3 !=nil{
		err = errors.New("Error in Marshalling")
		return
	}
	ivf := userlib.RandomBytes(16)
	cfdir1 := userlib.CFBEncrypter(userdata.SyK, ivf)
	cfdir1.XORKeyStream(mfdir, mfdir)//Encrypting File Directory
	mfdir = append(ivf, mfdir...)
	flmac1 := userlib.NewHMAC(userdata.PassH)
	flmac1.Write([]byte(userdata.Username))
	floc1 := flmac1.Sum(nil)// File location HMAC(username)
	fmac1 := userlib.NewHMAC(userdata.SyK)
	fmac1.Write(append(mfdir, floc1...))
	filemac := fmac1.Sum(nil)// HMAC(encrypted file directory + location)
	mfdir = append(filemac,mfdir...)
	userlib.DatastoreSet(string(floc1), []byte(string(mfdir)))//Storing encrypted file directory along with HMAC.
	err=nil

	return
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var ud User
	key, error := userlib.GenerateRSAKey()//Generating RSA Key pair
	if error != nil{
		err = errors.New("Error in RSA Key Generation")
		return
        }
	
	ud.Username = username
	ud.PrK = *key
	userlib.KeystoreSet(username, key.PublicKey)//Registering public key on the Key Store
	ud.SyK = userlib.Argon2Key(ud.PassH, []byte(username), 16)// Generating key for file directory
	ph := userlib.NewSHA256()
	ph.Write([]byte(password))
	ud.PassH = ph.Sum(nil)//Storing SHA256(password)
	
	kk := userlib.Argon2Key(append(ud.PassH, []byte(username)...), []byte(username), 16)//Key for encrypting User data structure
    
	udata, error2 := json.Marshal(ud)//Marshalling data
	if error2 != nil{
		err = errors.New("Error in Marshalling")
		return
	}
	
	iv := userlib.RandomBytes(16)	
	cuser := userlib.CFBEncrypter(kk, iv)
	cuser.XORKeyStream(udata, udata)//Encrypting user data
	udata = append(iv, udata...)
	sloc := userlib.NewSHA256()
	sloc.Write(append([]byte(username), ud.PassH...))
	uloc := sloc.Sum(nil)//Location of user data : SHA256( UN + SHA256(Password))
	hmac := userlib.NewHMAC(kk)
	hmac.Write(append(udata, uloc...) )
	umac := hmac.Sum(nil)// HMAC(encrypted user data + location of user data)

	mloc1 := userlib.NewSHA256()
	mloc1.Write(append(ud.PassH,[]byte(username)...))
	uloc1 := mloc1.Sum(nil)
	userlib.DatastoreSet(string(uloc1),umac)

	//udata = append(umac,udata...)
	userlib.DatastoreSet(string(uloc), []byte(string(udata)))
	userdataptr = &ud
	
	fdir := make(map[string]FileDir)
	mfdir, error3 := json.Marshal(fdir)
	if error3 !=nil{
		err = errors.New("Error in Marshalling")
		return
	}
	ivf := userlib.RandomBytes(16)
	cfdir := userlib.CFBEncrypter(ud.SyK, ivf)
	cfdir.XORKeyStream(mfdir, mfdir)//Encrypting File Directory
	mfdir = append(ivf, mfdir...)
	flmac := userlib.NewHMAC(ud.PassH)
	flmac.Write([]byte(username))
	floc := flmac.Sum(nil)// File location HMAC(username)
	fmac := userlib.NewHMAC(ud.SyK)
	fmac.Write(append(mfdir, floc...))
	filemac := fmac.Sum(nil)// HMAC(encrypted file directory + location)
	mfdir = append(filemac,mfdir...)
	userlib.DatastoreSet(string(floc), []byte(string(mfdir)))//Storing encrypted file directory along with HMAC.
	return
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	ph := userlib.NewSHA256()
	ph.Write([]byte(password))
	pass_hash := ph.Sum(nil)
	
	sloc := userlib.NewSHA256()
	sloc.Write(append([]byte(username), pass_hash...))
	uloc := sloc.Sum(nil)

	mloc1 := userlib.NewSHA256()
	mloc1.Write(append(pass_hash,[]byte(username)...))
	uloc1 := mloc1.Sum(nil)
	
	// Extract the encrypted user data and its hmac (placed before user data) from location uloc
	udata, ok := userlib.DatastoreGet(string(uloc))

	if !ok {
		err = errors.New("DataStoreGet error : Unable to fetch data from DataStore")
		return
	}

	/*stored_hmac := udata[:32]		// Extract the HMAC of the encrypted user data
	if len(stored_hmac)!=32{
		err = errors.New("HMAC changed")
		return
	}
	udata = udata[32:]*/
	stored_hmac,ok := userlib.DatastoreGet(string(uloc1))	
	if !ok {
		err = errors.New("DataStoreGet error : Unable to fetch data from DataStore")
		return
	}
	kk := userlib.Argon2Key(append(pass_hash, []byte(username)...), []byte(username), 16)
	hmac := userlib.NewHMAC(kk)
	hmac.Write(append(udata, uloc...) )
	umac := hmac.Sum(nil)// HMAC(encrypted user data + location of user data)
	if !(userlib.Equal(umac, stored_hmac)) {
		err = errors.New("HMAC did not match...User data corrupted \n or else incorrect username or password.")
		return
	}


	iv := udata[:16]				// Extract the initialization vector
	if len(iv)!=16{
		err = errors.New("IV Changed")
		return
	}
	encrypted_udata := udata[16:]		// Extract the encrytped user data
	dec_udata := userlib.CFBDecrypter(kk, iv)
	dec_udata.XORKeyStream(encrypted_udata, encrypted_udata)

	var ud User
	err4 := json.Unmarshal(encrypted_udata, &ud)
	if err4 != nil{
		err = errors.New("Unmarshalling failed")
		return
	}
	userdataptr = &ud
	return
}
/*

func SwapUser(un1 string, pwd1 string, un2 string, pwd2 string) (err error) {

	u1, err1 := GetUser(un1, pwd1)
	if err1 != nil {
		err = errors.New("failed to load the user")
		return
	}

	u2, err2 := GetUser(un2, pwd2)
	if err2 != nil {
		err = errors.New("failed to load the user")
		return
	}
	println(u1, u2)

	ph1 := userlib.NewSHA256()
	ph1.Write([]byte(pwd1))
	pass_hash1 := ph1.Sum(nil)
	sloc1 := userlib.NewSHA256()
	sloc1.Write(append([]byte(un1), pass_hash1...))
	uloc1 := sloc1.Sum(nil)
	udata1, ok := userlib.DatastoreGet(string(uloc1))
	// hiv1 := udata1[:48]
	// udata1 = udata1[48:]

	ph2 := userlib.NewSHA256()
	ph2.Write([]byte(pwd2))
	pass_hash2 := ph2.Sum(nil)
	sloc2 := userlib.NewSHA256()
	sloc2.Write(append([]byte(un2), pass_hash2...))
	uloc2 := sloc2.Sum(nil)	
	udata2, ok := userlib.DatastoreGet(string(uloc2))
	if !ok {
		err = errors.New("unable to get")
		return
	}
println("loaded user data:")
	println(string(udata1))

	println("\n")
	println(string(udata2))
println("\n")
	// hiv2 := udata2[:48]
	// udata2 = udata2[48:]
	
	// println(u1.Username)
	// println(u2.Username)
	userlib.DatastoreDelete(string(uloc1))
	userlib.DatastoreSet(string(uloc1), udata2)
	userlib.DatastoreDelete(string(uloc2))
	userlib.DatastoreSet(string(uloc2), udata1)
	return
}
*/