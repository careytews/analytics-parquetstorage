package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/trustnetworks/analytics-common/cloudstorage"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
)

const pgm = "parquetstorage"

// The queue consists of flat events plus the original event size.
type QueueItem struct {
	event *FlatEvent
	size  int
}

// Flat event queue size
const feQueueSize = 10000

var maxBatch int64
var maxTime float64
var ctx context.Context
var pqwr *Writer
var path string
var uid string
var tm string
var data bytes.Buffer

type work struct {
	storage      cloudstorage.CloudStorage // Platform-specific storage
	project      string
	basedir      string
	count        int64
	items        int64
	last         time.Time
	stripPayload bool
	feQueue      chan QueueItem
}

// TODO: this is identical to analytics-storage except for
// default batch size
func setMaxBatchSize() {
	var err error

	// Default file size, if no batch size env value set
	// Default of 64M is optimal value for our data
	var defaultMaxBatch int64 = 268435456 // 256 * 1024 * 1024
	var mBytes = false
	var kBytes = false

	// Get batch size env value and trim, remove spaces and M or K
	mBatchFromEnv := utils.Getenv("MAX_BATCH", "268435456")
	mBatch := strings.Replace(mBatchFromEnv, "\"", "", -1)
	if strings.Contains(strings.ToUpper(mBatch), "M") {
		mBatch = strings.Replace(strings.ToUpper(mBatch), "M", "", -1)
		mBytes = true
	} else if strings.Contains(strings.ToUpper(mBatch), "K") {
		mBatch = strings.Replace(strings.ToUpper(mBatch), "K", "", -1)
		kBytes = true
	}
	mBatch = strings.Replace(mBatch, " ", "", -1)
	mBatch = strings.TrimSpace(mBatch)

	// Check max batch size value set in env is parsable to int, if not use default value
	maxBatch, err = strconv.ParseInt(mBatch, 10, 64)
	if err != nil {
		maxBatch = defaultMaxBatch
		utils.Log("Couldn't parse MAX_BATCH: %v :using default %v", mBatchFromEnv, defaultMaxBatch)

	} else {
		if mBytes == true {
			if maxBatch < ((math.MaxInt64 / 1024) / 1024) {
				maxBatch = maxBatch * 1024 * 1024
			} else {
				utils.Log("Couldn't convert MAX_BATCH to Megabytes: %v :using default %v", mBatchFromEnv, defaultMaxBatch)
			}
		} else if kBytes == true {
			if maxBatch < (math.MaxInt64 / 1024) {
				maxBatch = maxBatch * 1024
			} else {
				utils.Log("Couldn't convert MAX_BATCH to Kilobytes: %v :using default %v", mBatchFromEnv, defaultMaxBatch)
			}
		}

	}

	utils.Log("maxBatch set to: %v", maxBatch)
}

// TODO: this is identical to code in analytics-storage
func setMaxTime() {
	var err error

	// Default max time if no max time env values set
	// Default of 30 mins is optimal for our data
	var defaultMaxTime float64 = 1800 // 30 mins

	// Get max time env value and trim, remove spaces
	mTimeFromEnv := utils.Getenv("MAX_TIME", "1800")
	mTime := strings.Replace(mTimeFromEnv, "\"", "", -1)
	mTime = strings.Replace(mTime, " ", "", -1)
	mTime = strings.TrimSpace(mTime)

	// Check max time value set in env is parsable to int, if not use default value
	maxTime, err = strconv.ParseFloat(mTime, 64)
	if err != nil {
		utils.Log("Couldn't parse MAX_TIME: %v :using default %v", mTimeFromEnv, defaultMaxTime)
		maxTime = defaultMaxTime
	}

	utils.Log("maxTime set to: %v", maxTime)
}

func (s *work) init() error {

	var err error

	s.feQueue = make(chan QueueItem, feQueueSize)

	setMaxBatchSize()
	setMaxTime()

	s.project = utils.Getenv("STORAGE_PROJECT", "")
	s.basedir = utils.Getenv("STORAGE_BASEDIR", "parquet")

	s.count = 0
	s.items = 0
	s.last = time.Now()

	s.stripPayload = utils.Getenv("STRIP_PAYLOAD", "false") == "true"

	s.storage = cloudstorage.New(utils.Getenv("PLATFORM", ""))
	s.storage.Init("STORAGE_BUCKET", "")

	//create parquet writer
	pqwr, err = NewWriter(&data)
	if err != nil {
		utils.Log("Couldn't create parquet writer: %s", err.Error())
	}

	return nil

}

func (s *work) Handle(msg []uint8, w *worker.Worker) error {

	var e dt.Event

	// Convert JSON object to internal object.
	err := json.Unmarshal(msg, &e)
	if err != nil {
		utils.Log("Couldn't unmarshall json: %s", err.Error())
		return nil
	}

	fl := Flattener{
		WritePayloads: false,
	}

	//flatten json event
	oe := fl.FlattenEvent(&e)

	s.feQueue <- QueueItem{event: oe, size: len(msg)}

	return nil

}

func (s *work) QueueHandler() error {

	for {

		oe := <-s.feQueue
		err := s.HandleQueueItem(oe)
		if err != nil {
			utils.Log("Couldn't process queue item: %s", err.Error())
		}

	}

}

func (s *work) HandleQueueItem(oe QueueItem) error {

	if (s.count > maxBatch) || (time.Since(s.last).Seconds() > maxTime) {

		//create a new bucket storage path
		tm = time.Now().Format("2006-01-02/15-04")
		uid = uuid.New().String()
		path := s.basedir + "/" + tm + "/" + uid + ".parquet"

		//close parquet writer
		err := pqwr.Close()
		if err != nil {
			utils.Log("Couldn't close parquet writer: %s", err.Error())
		}

		s.storage.Upload(path, data.Bytes())

		//clear buffer for the next batch data
		data.Reset()
		//create new parquet writer
		pqwr, err = NewWriter(&data)

		//reset counter and time
		s.last = time.Now()
		s.count = 0
		s.items = 0

	} else {

		s.count += int64(oe.size)
		s.items += 1

		/*if (s.items % 2500) == 0 {
			utils.Log("items=%d size=%d qlen=%d", s.items, s.count,
				len(s.feQueue))
		}*/

		//convert to parquet format using parquet writer
		err := pqwr.Write(*oe.event)
		if err != nil {
			utils.Log("Couldn't write in to buffer: %s", err.Error())
			return nil
		}
	}

	return nil

}

func (s *work) QueueSizeReporter() {
	for {
		qln := len(s.feQueue)
		if qln > 0 {
			utils.Log("qlen=%d", qln)
		}
		time.Sleep(time.Second * 1)
	}
}

func main() {

	var w worker.QueueWorker
	var s work
	utils.LogPgm = pgm

	utils.Log("Initialising...")

	err := s.init()
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	var input string
	var output []string

	if len(os.Args) > 0 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}

	// context to handle control of subroutines
	ctx := context.Background()
	ctx, cancel := utils.ContextWithSigterm(ctx)
	defer cancel()

	err = w.Initialise(ctx, input, output, pgm)
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	go s.QueueHandler()
	//go s.QueueSizeReporter()

	utils.Log("Initialisation complete.")

	// Invoke Wye event handling.
	err = w.Run(ctx, &s)
	if err != nil {
		utils.Log("error: Event handling failed with err: %s", err.Error())
	}

}
