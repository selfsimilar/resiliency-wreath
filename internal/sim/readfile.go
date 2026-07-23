package sim

import "os"

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
