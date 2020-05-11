package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"
//import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
//	someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

/*
func TestUserStorage(t *testing.T) { 
	u1, err1 := GetUser("", "fubar")
	if err1 != nil {
		t.Log("Cannot load data for invalid user",u1)
	}else{
		t.Error("Data loaded for invalid user", err1)
	}

	// add more test cases here
}


func TestFileStoreLoadAppend(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	_ := u1.StoreFile("file1", data1)
/*
	data2, _ := u1.LoadFile("file1",0) 
	

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	}else{
		t.Log("data is not corrupted")
	}

	// add test cases here
}
*/



func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)
//	v := []byte("This is a test")
	v := userlib.RandomBytes(8192)
        //t.Log("Length of random ",len(v))
	u.StoreFile("file1", v)
/*
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}*/
}
/*
func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}
*/
