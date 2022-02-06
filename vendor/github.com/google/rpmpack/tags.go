// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpmpack

// Define only tags which we actually use
// https://github.com/rpm-software-management/rpm/blob/master/lib/rpmtag.h
const (
	tagHeaderI18NTable = 0x64 // 100
	// Signature tags are obiously overlapping regular header tags..
	sigSHA256      = 0x0111 // 273
	sigSize        = 0x03e8 // 1000
	sigPGP         = 0x03ea // 1002
	sigPayloadSize = 0x03ef // 1007

	// https://github.com/rpm-software-management/rpm/blob/92eadae94c48928bca90693ad63c46ceda37d81f/rpmio/rpmpgp.h#L258
	hashAlgoSHA256 = 0x0008 // 8

	tagName        = 0x03e8 // 1000
	tagVersion     = 0x03e9 // 1001
	tagRelease     = 0x03ea // 1002
	tagEpoch       = 0x03eb // 1003
	tagSummary     = 0x03ec // 1004
	tagDescription = 0x03ed // 1005
	tagBuildTime   = 0x03ee // 1006
	tagBuildHost   = 0x03ef // 1007
	tagSize        = 0x03f1 // 1009
	tagVendor      = 0x03f3 // 1011
	tagLicence     = 0x03f6 // 1014
	tagPackager    = 0x03f7 // 1015
	tagGroup       = 0x03f8 // 1016
	tagURL         = 0x03fc // 1020
	tagOS          = 0x03fd // 1021
	tagArch        = 0x03fe // 1022

	tagPrein  = 0x03ff // 1023
	tagPostin = 0x0400 // 1024
	tagPreun  = 0x0401 // 1025
	tagPostun = 0x0402 // 1026

	tagFileSizes         = 0x0404 // 1028
	tagFileModes         = 0x0406 // 1030
	tagFileRDevs         = 0x0409 // 1033
	tagFileMTimes        = 0x040a // 1034
	tagFileDigests       = 0x040b // 1035
	tagFileLinkTos       = 0x040c // 1036
	tagFileFlags         = 0x040d // 1037
	tagFileUserName      = 0x040f // 1039
	tagFileGroupName     = 0x0410 // 1040
	tagSourceRPM         = 0x0414 // 1044
	tagFileVerifyFlags   = 0x0415 // 1045
	tagProvides          = 0x0417 // 1047
	tagRequireFlags      = 0x0418 // 1048
	tagRequires          = 0x0419 // 1049
	tagRequireVersion    = 0x041a // 1050
	tagConflictFlags     = 0x041d // 1053
	tagConflicts         = 0x041e // 1054
	tagConflictVersion   = 0x041f // 1055
	tagPreinProg         = 0x043d // 1085
	tagPostinProg        = 0x043e // 1086
	tagPreunProg         = 0x043f // 1087
	tagPostunProg        = 0x0440 // 1088
	tagObsoletes         = 0x0442 // 1090
	tagFileINodes        = 0x0448 // 1096
	tagFileLangs         = 0x0449 // 1097
	tagProvideFlags      = 0x0458 // 1112
	tagProvideVersion    = 0x0459 // 1113
	tagObsoleteFlags     = 0x045a // 1114
	tagObsoleteVersion   = 0x045b // 1115
	tagDirindexes        = 0x045c // 1116
	tagBasenames         = 0x045d // 1117
	tagDirnames          = 0x045e // 1118
	tagPayloadFormat     = 0x0464 // 1124
	tagPayloadCompressor = 0x0465 // 1125
	tagPayloadFlags      = 0x0466 // 1126
	tagFileDigestAlgo    = 0x1393 // 5011
	tagRecommends        = 0x13b6 // 5046
	tagRecommendVersion  = 0x13b7 // 5047
	tagRecommendFlags    = 0x13b8 // 5048
	tagSuggests          = 0x13b9 // 5049
	tagSuggestVersion    = 0x13ba // 5050
	tagSuggestFlags      = 0x13bb // 5051
	tagPayloadDigest     = 0x13e4 // 5092
	tagPayloadDigestAlgo = 0x13e5 // 5093
)
