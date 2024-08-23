package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("unable to create Casbin enforcer: %v", err)
	}

	sub := "alice" // the user that wants to access a resource.
	obj := "data"  // the resource that is going to be accessed.
	act := "read"  // the operation that the user performs on the resource.

	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		// handle err
		fmt.Println(err)
	}
	if ok == true {
		// permit alice to read data1
		fmt.Println("alice can read data")
	} else {
		// deny the request, show an error
		fmt.Println("alice cannot read data")
	}

	ok, err = e.Enforce("alice", "data", "write")
	if err != nil {
		// handle err
		fmt.Println(err)
	}
	if ok == true {
		// permit alice to read data1
		fmt.Println("alice can write data")
	} else {
		// deny the request, show an error
		fmt.Println("alice cannot write data")
	}

	ok, err = e.Enforce("alice", "secretdata", "read")
	if err != nil {
		// handle err
		fmt.Println(err)
	}
	if ok == true {
		// permit alice to read data1
		fmt.Println("alice can read secretdata")
	} else {
		// deny the request, show an error
		fmt.Println("alice cannot read secretdata")
	}

	// You could use BatchEnforce() to enforce some requests in batches.
	// This method returns a bool slice, and this slice's index corresponds to the row index of the two-dimensional array.
	// e.g. results[0] is the result of {"alice", "data1", "read"}
	results, err := e.BatchEnforce([][]interface{}{{"alice", "data", "read"}, {"bob", "data", "write"}, {"jack", "data", "read"}})
	if err != nil {
		// handle err
		fmt.Println(err)
	}

	for i, result := range results {
		if result {
			fmt.Printf("Request %d is permitted\n", i)
		} else {
			fmt.Printf("Request %d is denied\n", i)
		}
	}

	roles, err := e.GetRolesForUser("alice")
	if err != nil {
		// handle err
		fmt.Println(err)
	}

	for _, role := range roles {
		fmt.Println(role)
	}

}
