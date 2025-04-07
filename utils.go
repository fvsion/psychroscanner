package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "os"
    "os/exec"
    "regexp"
    "strings"
    "sync"
    "time"
)

func parseTargets() error {
    if targetFile != "" {
        file, err := os.Open(targetFile)
        if err != nil {
            return fmt.Errorf("error: target file '%s' not found", targetFile)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line == "" || strings.HasPrefix(line, "#") {
                continue
            }
            targets = append(targets, line)
        }
        if err := scanner.Err(); err != nil {
            return err
        }
    } else if len(flag.Args()) > 0 {
        targets = flag.Args()
    } else {
        return fmt.Errorf("error: no targets provided\nusage: %s [options] [target1 target2 ...]", os.Args[0])
    }

    if len(targets) == 0 {
        return fmt.Errorf("error: no valid targets provided")
    }

    return nil
}

func loadingBar(message string, doneChan chan bool, estTimeChan chan string, wg *sync.WaitGroup) {
    defer wg.Done()
    spinChars := []rune{'|', '/', '-', '\\'}
    i := 0
    var estTime string
    for {
        select {
        case <-doneChan:
            fmt.Printf("\r%s Done!                   \n", message)
            return
        case est := <-estTimeChan:
            estTime = est
        default:
            if estTime != "" {
                fmt.Printf("\r%s [%c] (Estimated time remaining: %s) ", message, spinChars[i%len(spinChars)], estTime)
            } else {
                fmt.Printf("\r%s [%c] ", message, spinChars[i%len(spinChars)])
            }
            i++
            if i >= len(spinChars) {
                i = 0
            }
            time.Sleep(500 * time.Millisecond)
        }
    }
}

func runCommand(cmdArgs []string, message string, verboseFile string) error {
    cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
    stdoutPipe, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }

    stderrPipe, err := cmd.StderrPipe()
    if err != nil {
        return err
    }

    if err := cmd.Start(); err != nil {
        return err
    }

    // Create or truncate the verbose file
    verboseFileHandle, err := os.Create(verboseFile)
    if err != nil {
        return err
    }
    defer verboseFileHandle.Close()

    var wg sync.WaitGroup
    wg.Add(1)
    loadingDone := make(chan bool)
    estTimeChan := make(chan string)
    go loadingBar(message, loadingDone, estTimeChan, &wg)

    // Combine stdout and stderr
    outputPipe := io.MultiReader(stdoutPipe, stderrPipe)
    go func() {
        scanner := bufio.NewScanner(outputPipe)
        estTimeRegex := regexp.MustCompile(`(?i)About [\d.]+%.*?ETC:.*?\((.*?) remaining\)`)
        for scanner.Scan() {
            line := scanner.Text()
            verboseFileHandle.WriteString(line + "\n")

            if debugMode {
                fmt.Println("DEBUG:", line)
            }

            // Parse estimated remaining time
            if matches := estTimeRegex.FindStringSubmatch(line); len(matches) > 1 {
                estTimeChan <- matches[1]
                if debugMode {
                    fmt.Println("DEBUG: Matched estimated time remaining:", matches[1])
                }
            }
        }
    }()

    if err := cmd.Wait(); err != nil {
        loadingDone <- true
        wg.Wait()
        return err
    }

    loadingDone <- true
    wg.Wait()
    return nil
}

