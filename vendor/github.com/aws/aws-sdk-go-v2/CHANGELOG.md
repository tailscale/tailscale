# Release (2021-12-02)

## General Highlights
* **Bug Fix**: Fixes a bug that prevented aws.EndpointResolverWithOptions from being used by the service client. ([#1514](https://github.com/aws/aws-sdk-go-v2/pull/1514))
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/config`: [v1.11.0](config/CHANGELOG.md#v1110-2021-12-02)
  * **Feature**: Add support for specifying `EndpointResolverWithOptions` on `LoadOptions`, and associated `WithEndpointResolverWithOptions`.
* `github.com/aws/aws-sdk-go-v2/service/accessanalyzer`: [v1.10.0](service/accessanalyzer/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/applicationinsights`: [v1.9.0](service/applicationinsights/CHANGELOG.md#v190-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/backupgateway`: [v1.0.0](service/backupgateway/CHANGELOG.md#v100-2021-12-02)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/cloudhsm`: [v1.8.0](service/cloudhsm/CHANGELOG.md#v180-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/devopsguru`: [v1.11.0](service/devopsguru/CHANGELOG.md#v1110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/directconnect`: [v1.12.0](service/directconnect/CHANGELOG.md#v1120-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dynamodb`: [v1.10.0](service/dynamodb/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.25.0](service/ec2/CHANGELOG.md#v1250-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/evidently`: [v1.1.0](service/evidently/CHANGELOG.md#v110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.14.0](service/fsx/CHANGELOG.md#v1140-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.16.0](service/glue/CHANGELOG.md#v1160-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/inspector2`: [v1.1.0](service/inspector2/CHANGELOG.md#v110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.18.0](service/iot/CHANGELOG.md#v1180-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iottwinmaker`: [v1.0.0](service/iottwinmaker/CHANGELOG.md#v100-2021-12-02)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/kafka`: [v1.11.0](service/kafka/CHANGELOG.md#v1110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.17.0](service/kendra/CHANGELOG.md#v1170-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesis`: [v1.10.0](service/kinesis/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lakeformation`: [v1.10.0](service/lakeformation/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.14.0](service/lexmodelsv2/CHANGELOG.md#v1140-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.10.0](service/lexruntimev2/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: Support has been added for the `StartConversation` API.
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.12.0](service/outposts/CHANGELOG.md#v1120-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rbin`: [v1.1.0](service/rbin/CHANGELOG.md#v110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshiftdata`: [v1.10.0](service/redshiftdata/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rum`: [v1.1.0](service/rum/CHANGELOG.md#v110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.21.0](service/s3/CHANGELOG.md#v1210-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.20.0](service/sagemaker/CHANGELOG.md#v1200-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemakerruntime`: [v1.11.0](service/sagemakerruntime/CHANGELOG.md#v1110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/shield`: [v1.11.0](service/shield/CHANGELOG.md#v1110-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/snowball`: [v1.10.0](service/snowball/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/storagegateway`: [v1.10.0](service/storagegateway/CHANGELOG.md#v1100-2021-12-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workspacesweb`: [v1.0.0](service/workspacesweb/CHANGELOG.md#v100-2021-12-02)
  * **Release**: New AWS service client module

# Release (2021-11-30)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.16.0](service/autoscaling/CHANGELOG.md#v1160-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/backup`: [v1.10.0](service/backup/CHANGELOG.md#v1100-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/braket`: [v1.10.0](service/braket/CHANGELOG.md#v1100-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmeetings`: [v1.2.0](service/chimesdkmeetings/CHANGELOG.md#v120-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.15.0](service/cloudformation/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.13.0](service/computeoptimizer/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.13.0](service/connect/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/customerprofiles`: [v1.12.0](service/customerprofiles/CHANGELOG.md#v1120-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.13.0](service/databasemigrationservice/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dataexchange`: [v1.9.0](service/dataexchange/CHANGELOG.md#v190-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dynamodb`: [v1.9.0](service/dynamodb/CHANGELOG.md#v190-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.24.0](service/ec2/CHANGELOG.md#v1240-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecr`: [v1.11.0](service/ecr/CHANGELOG.md#v1110-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.13.0](service/ecs/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.15.0](service/eks/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.15.0](service/elasticache/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.13.0](service/elasticloadbalancingv2/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticsearchservice`: [v1.10.0](service/elasticsearchservice/CHANGELOG.md#v1100-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/evidently`: [v1.0.0](service/evidently/CHANGELOG.md#v100-2021-11-30)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/finspacedata`: [v1.5.0](service/finspacedata/CHANGELOG.md#v150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.14.0](service/imagebuilder/CHANGELOG.md#v1140-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/inspector2`: [v1.0.0](service/inspector2/CHANGELOG.md#v100-2021-11-30)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery`: [v1.3.2](service/internal/endpoint-discovery/CHANGELOG.md#v132-2021-11-30)
  * **Bug Fix**: Fixed a race condition that caused concurrent calls relying on endpoint discovery to share the same `url.URL` reference in their operation's http.Request.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.17.0](service/iot/CHANGELOG.md#v1170-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotdeviceadvisor`: [v1.9.0](service/iotdeviceadvisor/CHANGELOG.md#v190-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.15.0](service/iotsitewise/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotwireless`: [v1.13.0](service/iotwireless/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.14.0](service/lambda/CHANGELOG.md#v1140-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.14.0](service/macie2/CHANGELOG.md#v1140-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mgn`: [v1.8.0](service/mgn/CHANGELOG.md#v180-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/migrationhubrefactorspaces`: [v1.0.0](service/migrationhubrefactorspaces/CHANGELOG.md#v100-2021-11-30)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/opensearch`: [v1.4.0](service/opensearch/CHANGELOG.md#v140-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.11.0](service/outposts/CHANGELOG.md#v1110-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/personalize`: [v1.12.0](service/personalize/CHANGELOG.md#v1120-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/personalizeruntime`: [v1.7.0](service/personalizeruntime/CHANGELOG.md#v170-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/pinpoint`: [v1.12.0](service/pinpoint/CHANGELOG.md#v1120-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/proton`: [v1.7.0](service/proton/CHANGELOG.md#v170-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.15.0](service/quicksight/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rbin`: [v1.0.0](service/rbin/CHANGELOG.md#v100-2021-11-30)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.13.0](service/rds/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.16.0](service/redshift/CHANGELOG.md#v1160-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rum`: [v1.0.0](service/rum/CHANGELOG.md#v100-2021-11-30)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.20.0](service/s3/CHANGELOG.md#v1200-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.15.0](service/s3control/CHANGELOG.md#v1150-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.13.0](service/sqs/CHANGELOG.md#v1130-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.17.0](service/ssm/CHANGELOG.md#v1170-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sts`: [v1.11.0](service/sts/CHANGELOG.md#v1110-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/textract`: [v1.10.0](service/textract/CHANGELOG.md#v1100-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/timestreamquery`: [v1.8.0](service/timestreamquery/CHANGELOG.md#v180-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/timestreamwrite`: [v1.8.0](service/timestreamwrite/CHANGELOG.md#v180-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/transcribestreaming`: [v1.1.0](service/transcribestreaming/CHANGELOG.md#v110-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/translate`: [v1.8.0](service/translate/CHANGELOG.md#v180-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wellarchitected`: [v1.9.0](service/wellarchitected/CHANGELOG.md#v190-2021-11-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workspaces`: [v1.11.0](service/workspaces/CHANGELOG.md#v1110-2021-11-30)
  * **Feature**: API client updated

# Release (2021-11-19)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.11.1
  * **Bug Fix**: Fixed a bug that prevented aws.EndpointResolverWithOptionsFunc from satisfying the aws.EndpointResolverWithOptions interface.
* `github.com/aws/aws-sdk-go-v2/service/amplifybackend`: [v1.8.0](service/amplifybackend/CHANGELOG.md#v180-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/apigateway`: [v1.10.0](service/apigateway/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appconfig`: [v1.7.0](service/appconfig/CHANGELOG.md#v170-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appconfigdata`: [v1.0.0](service/appconfigdata/CHANGELOG.md#v100-2021-11-19)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/applicationinsights`: [v1.8.0](service/applicationinsights/CHANGELOG.md#v180-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appstream`: [v1.10.0](service/appstream/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/auditmanager`: [v1.12.0](service/auditmanager/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/batch`: [v1.11.0](service/batch/CHANGELOG.md#v1110-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.14.0](service/chime/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmeetings`: [v1.1.0](service/chimesdkmeetings/CHANGELOG.md#v110-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.14.0](service/cloudformation/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudtrail`: [v1.10.0](service/cloudtrail/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatch`: [v1.12.0](service/cloudwatch/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.12.0](service/connect/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.12.0](service/databasemigrationservice/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databrew`: [v1.13.0](service/databrew/CHANGELOG.md#v1130-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/devopsguru`: [v1.10.0](service/devopsguru/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/drs`: [v1.0.0](service/drs/CHANGELOG.md#v100-2021-11-19)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/dynamodbstreams`: [v1.8.0](service/dynamodbstreams/CHANGELOG.md#v180-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.23.0](service/ec2/CHANGELOG.md#v1230-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.14.0](service/eks/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/forecast`: [v1.14.0](service/forecast/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ivs`: [v1.10.0](service/ivs/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kafka`: [v1.10.0](service/kafka/CHANGELOG.md#v1100-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.16.0](service/kendra/CHANGELOG.md#v1160-2021-11-19)
  * **Announcement**: Fix API modeling bug incorrectly generating `DocumentAttributeValue` type as a union instead of a structure. This update corrects this bug by correcting the `DocumentAttributeValue` type to be a `struct` instead of an `interface`. This change also removes the `DocumentAttributeValueMember` types. To migrate to this change your application using service/kendra will need to be updated to use struct members in `DocumentAttributeValue` instead of `DocumentAttributeValueMember` types.
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.11.0](service/kms/CHANGELOG.md#v1110-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.13.0](service/lambda/CHANGELOG.md#v1130-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.13.0](service/lexmodelsv2/CHANGELOG.md#v1130-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.9.0](service/lexruntimev2/CHANGELOG.md#v190-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/location`: [v1.9.0](service/location/CHANGELOG.md#v190-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.15.0](service/mediaconvert/CHANGELOG.md#v1150-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/medialive`: [v1.14.0](service/medialive/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mgn`: [v1.7.0](service/mgn/CHANGELOG.md#v170-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/migrationhubstrategy`: [v1.0.0](service/migrationhubstrategy/CHANGELOG.md#v100-2021-11-19)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/qldb`: [v1.9.0](service/qldb/CHANGELOG.md#v190-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/qldbsession`: [v1.9.0](service/qldbsession/CHANGELOG.md#v190-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.15.0](service/redshift/CHANGELOG.md#v1150-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sns`: [v1.12.0](service/sns/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.16.0](service/ssm/CHANGELOG.md#v1160-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.12.0](service/transfer/CHANGELOG.md#v1120-2021-11-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.14.0](service/wafv2/CHANGELOG.md#v1140-2021-11-19)
  * **Feature**: API client updated

# Release (2021-11-12)

## General Highlights
* **Feature**: Service clients now support custom endpoints that have an initial URI path defined.
* **Feature**: Waiters now have a `WaitForOutput` method, which can be used to retrieve the output of the successful wait operation. Thank you to [Andrew Haines](https://github.com/haines) for contributing this feature.
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/backup`: [v1.9.0](service/backup/CHANGELOG.md#v190-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/batch`: [v1.10.0](service/batch/CHANGELOG.md#v1100-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmeetings`: [v1.0.0](service/chimesdkmeetings/CHANGELOG.md#v100-2021-11-12)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.12.0](service/computeoptimizer/CHANGELOG.md#v1120-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.11.0](service/connect/CHANGELOG.md#v1110-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.12.0](service/docdb/CHANGELOG.md#v1120-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/dynamodb`: [v1.8.0](service/dynamodb/CHANGELOG.md#v180-2021-11-12)
  * **Documentation**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.22.0](service/ec2/CHANGELOG.md#v1220-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.12.0](service/ecs/CHANGELOG.md#v1120-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/gamelift`: [v1.9.0](service/gamelift/CHANGELOG.md#v190-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/greengrassv2`: [v1.9.0](service/greengrassv2/CHANGELOG.md#v190-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/health`: [v1.10.0](service/health/CHANGELOG.md#v1100-2021-11-12)
  * **Documentation**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/identitystore`: [v1.9.0](service/identitystore/CHANGELOG.md#v190-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotwireless`: [v1.12.0](service/iotwireless/CHANGELOG.md#v1120-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.11.0](service/neptune/CHANGELOG.md#v1110-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.12.0](service/rds/CHANGELOG.md#v1120-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/resiliencehub`: [v1.0.0](service/resiliencehub/CHANGELOG.md#v100-2021-11-12)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi`: [v1.8.0](service/resourcegroupstaggingapi/CHANGELOG.md#v180-2021-11-12)
  * **Documentation**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.14.0](service/s3control/CHANGELOG.md#v1140-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.19.0](service/sagemaker/CHANGELOG.md#v1190-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sagemakerruntime`: [v1.10.0](service/sagemakerruntime/CHANGELOG.md#v1100-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssmincidents`: [v1.7.0](service/ssmincidents/CHANGELOG.md#v170-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.11.0](service/transcribe/CHANGELOG.md#v1110-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/translate`: [v1.7.0](service/translate/CHANGELOG.md#v170-2021-11-12)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.13.0](service/wafv2/CHANGELOG.md#v1130-2021-11-12)
  * **Feature**: Updated service to latest API model.

# Release (2021-11-06)

## General Highlights
* **Feature**: The SDK now supports configuration of FIPS and DualStack endpoints using environment variables, shared configuration, or programmatically.
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream`: [v1.0.0](aws/protocol/eventstream/CHANGELOG.md#v100-2021-11-06)
  * **Announcement**: Support has been added for AWS EventStream APIs for Kinesis, S3, and Transcribe Streaming. Support for the Lex Runtime V2 EventStream API will be added in a future release.
  * **Release**: Protocol support has been added for AWS event stream.
* `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2`: [v2.0.0](internal/endpoints/v2/CHANGELOG.md#v200-2021-11-06)
  * **Release**: Endpoint Variant Model Support
* `github.com/aws/aws-sdk-go-v2/service/applicationinsights`: [v1.6.0](service/applicationinsights/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/appstream`: [v1.8.0](service/appstream/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/auditmanager`: [v1.11.0](service/auditmanager/CHANGELOG.md#v1110-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.14.0](service/autoscaling/CHANGELOG.md#v1140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.13.0](service/chime/CHANGELOG.md#v1130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/chimesdkidentity`: [v1.4.0](service/chimesdkidentity/CHANGELOG.md#v140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmessaging`: [v1.4.0](service/chimesdkmessaging/CHANGELOG.md#v140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudfront`: [v1.10.0](service/cloudfront/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/codecommit`: [v1.7.0](service/codecommit/CHANGELOG.md#v170-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.10.0](service/connect/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/connectcontactlens`: [v1.7.0](service/connectcontactlens/CHANGELOG.md#v170-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/connectparticipant`: [v1.6.0](service/connectparticipant/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.10.0](service/databasemigrationservice/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/datasync`: [v1.8.0](service/datasync/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.11.0](service/docdb/CHANGELOG.md#v1110-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ebs`: [v1.9.0](service/ebs/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.21.0](service/ec2/CHANGELOG.md#v1210-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ecr`: [v1.9.0](service/ecr/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.11.0](service/ecs/CHANGELOG.md#v1110-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.12.0](service/eks/CHANGELOG.md#v1120-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.13.0](service/elasticache/CHANGELOG.md#v1130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/elasticsearchservice`: [v1.9.0](service/elasticsearchservice/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/emrcontainers`: [v1.8.0](service/emrcontainers/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/finspace`: [v1.4.0](service/finspace/CHANGELOG.md#v140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.12.0](service/fsx/CHANGELOG.md#v1120-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/gamelift`: [v1.8.0](service/gamelift/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/health`: [v1.9.0](service/health/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.12.0](service/iam/CHANGELOG.md#v1120-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/internal/eventstreamtesting`: [v1.0.0](service/internal/eventstreamtesting/CHANGELOG.md#v100-2021-11-06)
  * **Release**: Protocol support has been added for AWS event stream.
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.13.0](service/iotsitewise/CHANGELOG.md#v1130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.14.0](service/kendra/CHANGELOG.md#v1140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/kinesis`: [v1.8.0](service/kinesis/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Support has been added for the SubscribeToShard API.
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.9.0](service/kms/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.12.0](service/lightsail/CHANGELOG.md#v1120-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.13.0](service/macie2/CHANGELOG.md#v1130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/mgn`: [v1.6.0](service/mgn/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.10.0](service/neptune/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/networkmanager`: [v1.6.0](service/networkmanager/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/nimble`: [v1.6.0](service/nimble/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/opensearch`: [v1.3.0](service/opensearch/CHANGELOG.md#v130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.14.0](service/quicksight/CHANGELOG.md#v1140-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.11.0](service/rds/CHANGELOG.md#v1110-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/rekognition`: [v1.10.0](service/rekognition/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53resolver`: [v1.9.0](service/route53resolver/CHANGELOG.md#v190-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.18.0](service/s3/CHANGELOG.md#v1180-2021-11-06)
  * **Feature**: Support has been added for the SelectObjectContent API.
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.13.0](service/s3control/CHANGELOG.md#v1130-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.18.0](service/sagemaker/CHANGELOG.md#v1180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/servicediscovery`: [v1.11.0](service/servicediscovery/CHANGELOG.md#v1110-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssmincidents`: [v1.6.0](service/ssmincidents/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sso`: [v1.6.0](service/sso/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/storagegateway`: [v1.8.0](service/storagegateway/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/support`: [v1.7.0](service/support/CHANGELOG.md#v170-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/textract`: [v1.8.0](service/textract/CHANGELOG.md#v180-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.10.0](service/transcribe/CHANGELOG.md#v1100-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/transcribestreaming`: [v1.0.0](service/transcribestreaming/CHANGELOG.md#v100-2021-11-06)
  * **Release**: New AWS service client module
  * **Feature**: Support has been added for the StartStreamTranscription and StartMedicalStreamTranscription APIs.
* `github.com/aws/aws-sdk-go-v2/service/waf`: [v1.6.0](service/waf/CHANGELOG.md#v160-2021-11-06)
  * **Feature**: Updated service to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/wisdom`: [v1.2.0](service/wisdom/CHANGELOG.md#v120-2021-11-06)
  * **Feature**: Updated service to latest API model.

# Release (2021-10-21)

## General Highlights
* **Feature**: Updated  to latest version
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.10.0
  * **Feature**: Adds dynamic signing middleware that switches to unsigned payload when TLS is enabled.
* `github.com/aws/aws-sdk-go-v2/service/appflow`: [v1.8.0](service/appflow/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/applicationautoscaling`: [v1.8.0](service/applicationautoscaling/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.13.0](service/autoscaling/CHANGELOG.md#v1130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmessaging`: [v1.3.0](service/chimesdkmessaging/CHANGELOG.md#v130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.11.0](service/cloudformation/CHANGELOG.md#v1110-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudsearch`: [v1.7.0](service/cloudsearch/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudtrail`: [v1.7.0](service/cloudtrail/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatch`: [v1.9.0](service/cloudwatch/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchevents`: [v1.7.0](service/cloudwatchevents/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs`: [v1.8.0](service/cloudwatchlogs/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codedeploy`: [v1.7.0](service/codedeploy/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/configservice`: [v1.10.0](service/configservice/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dataexchange`: [v1.7.0](service/dataexchange/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/directconnect`: [v1.9.0](service/directconnect/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.10.0](service/docdb/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dynamodb`: [v1.6.0](service/dynamodb/CHANGELOG.md#v160-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.20.0](service/ec2/CHANGELOG.md#v1200-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecr`: [v1.8.0](service/ecr/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.10.0](service/ecs/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/efs`: [v1.9.0](service/efs/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.12.0](service/elasticache/CHANGELOG.md#v1120-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing`: [v1.7.0](service/elasticloadbalancing/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.10.0](service/elasticloadbalancingv2/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/emr`: [v1.10.0](service/emr/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eventbridge`: [v1.8.0](service/eventbridge/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/glacier`: [v1.6.0](service/glacier/CHANGELOG.md#v160-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.13.0](service/glue/CHANGELOG.md#v1130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ivs`: [v1.8.0](service/ivs/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.13.0](service/kendra/CHANGELOG.md#v1130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesis`: [v1.7.0](service/kinesis/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2`: [v1.7.0](service/kinesisanalyticsv2/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.8.0](service/kms/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.10.0](service/lambda/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.13.0](service/mediaconvert/CHANGELOG.md#v1130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediapackage`: [v1.9.0](service/mediapackage/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediapackagevod`: [v1.10.0](service/mediapackagevod/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediatailor`: [v1.9.0](service/mediatailor/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.9.0](service/neptune/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/panorama`: [v1.0.0](service/panorama/CHANGELOG.md#v100-2021-10-21)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.13.0](service/quicksight/CHANGELOG.md#v1130-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.10.0](service/rds/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.12.0](service/redshift/CHANGELOG.md#v1120-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/robomaker`: [v1.10.0](service/robomaker/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.17.0](service/s3/CHANGELOG.md#v1170-2021-10-21)
  * **Feature**: Updates S3 streaming operations - PutObject, UploadPart, WriteGetObjectResponse to use unsigned payload signing auth when TLS is enabled.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.17.0](service/sagemaker/CHANGELOG.md#v1170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.12.0](service/securityhub/CHANGELOG.md#v1120-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sfn`: [v1.6.0](service/sfn/CHANGELOG.md#v160-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sns`: [v1.9.0](service/sns/CHANGELOG.md#v190-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.10.0](service/sqs/CHANGELOG.md#v1100-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/storagegateway`: [v1.7.0](service/storagegateway/CHANGELOG.md#v170-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sts`: [v1.8.0](service/sts/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/swf`: [v1.6.0](service/swf/CHANGELOG.md#v160-2021-10-21)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workmail`: [v1.8.0](service/workmail/CHANGELOG.md#v180-2021-10-21)
  * **Feature**: API client updated

# Release (2021-10-11)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/feature/ec2/imds`: [v1.6.0](feature/ec2/imds/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: Respect passed in Context Deadline/Timeout. Updates the IMDS Client operations to not override the passed in Context's Deadline or Timeout options. If an Client operation is called with a Context with a Deadline or Timeout, the client will no longer override it with the client's default timeout.
  * **Bug Fix**: Fix IMDS client's response handling and operation timeout race. Fixes #1253
* `github.com/aws/aws-sdk-go-v2/service/amplifybackend`: [v1.5.0](service/amplifybackend/CHANGELOG.md#v150-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/applicationautoscaling`: [v1.7.0](service/applicationautoscaling/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/apprunner`: [v1.3.0](service/apprunner/CHANGELOG.md#v130-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/backup`: [v1.6.0](service/backup/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.11.0](service/chime/CHANGELOG.md#v1110-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.11.0](service/codebuild/CHANGELOG.md#v1110-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databrew`: [v1.10.0](service/databrew/CHANGELOG.md#v1100-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.19.0](service/ec2/CHANGELOG.md#v1190-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/efs`: [v1.8.0](service/efs/CHANGELOG.md#v180-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.9.0](service/elasticloadbalancingv2/CHANGELOG.md#v190-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/firehose`: [v1.7.0](service/firehose/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/frauddetector`: [v1.10.0](service/frauddetector/CHANGELOG.md#v1100-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.10.0](service/fsx/CHANGELOG.md#v1100-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.12.0](service/glue/CHANGELOG.md#v1120-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/grafana`: [v1.0.0](service/grafana/CHANGELOG.md#v100-2021-10-11)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotevents`: [v1.8.0](service/iotevents/CHANGELOG.md#v180-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.12.0](service/kendra/CHANGELOG.md#v1120-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.7.0](service/kms/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.9.0](service/lexmodelsv2/CHANGELOG.md#v190-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.6.0](service/lexruntimev2/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/location`: [v1.6.0](service/location/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.12.0](service/mediaconvert/CHANGELOG.md#v1120-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/medialive`: [v1.10.0](service/medialive/CHANGELOG.md#v1100-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.16.0](service/sagemaker/CHANGELOG.md#v1160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/secretsmanager`: [v1.7.0](service/secretsmanager/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.11.0](service/securityhub/CHANGELOG.md#v1110-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.12.0](service/ssm/CHANGELOG.md#v1120-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssooidc`: [v1.6.0](service/ssooidc/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/synthetics`: [v1.7.0](service/synthetics/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/textract`: [v1.6.0](service/textract/CHANGELOG.md#v160-2021-10-11)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workmail`: [v1.7.0](service/workmail/CHANGELOG.md#v170-2021-10-11)
  * **Feature**: API client updated

# Release (2021-09-30)

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/account`: [v1.0.0](service/account/CHANGELOG.md#v100-2021-09-30)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/amp`: [v1.6.0](service/amp/CHANGELOG.md#v160-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appintegrations`: [v1.7.0](service/appintegrations/CHANGELOG.md#v170-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudcontrol`: [v1.0.0](service/cloudcontrol/CHANGELOG.md#v100-2021-09-30)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudhsmv2`: [v1.5.0](service/cloudhsmv2/CHANGELOG.md#v150-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.8.0](service/connect/CHANGELOG.md#v180-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dataexchange`: [v1.6.0](service/dataexchange/CHANGELOG.md#v160-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.8.0](service/elasticloadbalancingv2/CHANGELOG.md#v180-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.11.0](service/imagebuilder/CHANGELOG.md#v1110-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.9.0](service/lambda/CHANGELOG.md#v190-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.11.0](service/macie2/CHANGELOG.md#v1110-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/networkfirewall`: [v1.7.0](service/networkfirewall/CHANGELOG.md#v170-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/pinpoint`: [v1.8.0](service/pinpoint/CHANGELOG.md#v180-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sesv2`: [v1.6.0](service/sesv2/CHANGELOG.md#v160-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.8.0](service/transfer/CHANGELOG.md#v180-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/voiceid`: [v1.0.0](service/voiceid/CHANGELOG.md#v100-2021-09-30)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wisdom`: [v1.0.0](service/wisdom/CHANGELOG.md#v100-2021-09-30)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workmail`: [v1.6.0](service/workmail/CHANGELOG.md#v160-2021-09-30)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workspaces`: [v1.7.0](service/workspaces/CHANGELOG.md#v170-2021-09-30)
  * **Feature**: API client updated

# Release (2021-09-24)

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression`: [v1.2.4](feature/dynamodb/expression/CHANGELOG.md#v124-2021-09-24)
  * **Documentation**: Fixes typo in NameBuilder.NamesList example documentation to use the correct variable name.
* `github.com/aws/aws-sdk-go-v2/service/appmesh`: [v1.6.0](service/appmesh/CHANGELOG.md#v160-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appsync`: [v1.7.0](service/appsync/CHANGELOG.md#v170-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/auditmanager`: [v1.9.0](service/auditmanager/CHANGELOG.md#v190-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codecommit`: [v1.5.0](service/codecommit/CHANGELOG.md#v150-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/comprehend`: [v1.8.0](service/comprehend/CHANGELOG.md#v180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.8.0](service/databasemigrationservice/CHANGELOG.md#v180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.18.0](service/ec2/CHANGELOG.md#v1180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecr`: [v1.7.0](service/ecr/CHANGELOG.md#v170-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticsearchservice`: [v1.7.0](service/elasticsearchservice/CHANGELOG.md#v170-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.10.0](service/iam/CHANGELOG.md#v1100-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/identitystore`: [v1.6.0](service/identitystore/CHANGELOG.md#v160-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.10.0](service/imagebuilder/CHANGELOG.md#v1100-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.13.0](service/iot/CHANGELOG.md#v1130-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotevents`: [v1.7.0](service/iotevents/CHANGELOG.md#v170-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kafkaconnect`: [v1.1.0](service/kafkaconnect/CHANGELOG.md#v110-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lakeformation`: [v1.6.0](service/lakeformation/CHANGELOG.md#v160-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.8.0](service/lexmodelsv2/CHANGELOG.md#v180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.5.0](service/lexruntimev2/CHANGELOG.md#v150-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/licensemanager`: [v1.8.0](service/licensemanager/CHANGELOG.md#v180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.11.0](service/mediaconvert/CHANGELOG.md#v1110-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediapackagevod`: [v1.9.0](service/mediapackagevod/CHANGELOG.md#v190-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediatailor`: [v1.8.0](service/mediatailor/CHANGELOG.md#v180-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/opensearch`: [v1.1.0](service/opensearch/CHANGELOG.md#v110-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.12.0](service/quicksight/CHANGELOG.md#v1120-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.11.0](service/ssm/CHANGELOG.md#v1110-2021-09-24)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.10.0](service/wafv2/CHANGELOG.md#v1100-2021-09-24)
  * **Feature**: API client updated

# Release (2021-09-17)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.10.0](service/chime/CHANGELOG.md#v1100-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.10.1](service/cloudformation/CHANGELOG.md#v1101-2021-09-17)
  * **Documentation**: Updated API client documentation.
* `github.com/aws/aws-sdk-go-v2/service/comprehend`: [v1.7.0](service/comprehend/CHANGELOG.md#v170-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.17.0](service/ec2/CHANGELOG.md#v1170-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ecr`: [v1.6.0](service/ecr/CHANGELOG.md#v160-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.12.0](service/iot/CHANGELOG.md#v1120-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/kafkaconnect`: [v1.0.0](service/kafkaconnect/CHANGELOG.md#v100-2021-09-17)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.7.0](service/lexmodelsv2/CHANGELOG.md#v170-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.4.0](service/lexruntimev2/CHANGELOG.md#v140-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.10.0](service/macie2/CHANGELOG.md#v1100-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mediapackagevod`: [v1.8.0](service/mediapackagevod/CHANGELOG.md#v180-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/networkfirewall`: [v1.6.0](service/networkfirewall/CHANGELOG.md#v160-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/pinpoint`: [v1.7.0](service/pinpoint/CHANGELOG.md#v170-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.11.0](service/quicksight/CHANGELOG.md#v1110-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.9.0](service/rds/CHANGELOG.md#v190-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/robomaker`: [v1.9.0](service/robomaker/CHANGELOG.md#v190-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.16.0](service/s3/CHANGELOG.md#v1160-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.15.0](service/sagemaker/CHANGELOG.md#v1150-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ssooidc`: [v1.5.0](service/ssooidc/CHANGELOG.md#v150-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.8.0](service/transcribe/CHANGELOG.md#v180-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.9.0](service/wafv2/CHANGELOG.md#v190-2021-09-17)
  * **Feature**: Updated API client and endpoints to latest revision.

# Release (2021-09-10)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/credentials`: [v1.4.1](credentials/CHANGELOG.md#v141-2021-09-10)
  * **Documentation**: Fixes the AssumeRoleProvider's documentation for using custom TokenProviders.
* `github.com/aws/aws-sdk-go-v2/service/amp`: [v1.5.0](service/amp/CHANGELOG.md#v150-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/braket`: [v1.7.0](service/braket/CHANGELOG.md#v170-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkidentity`: [v1.2.0](service/chimesdkidentity/CHANGELOG.md#v120-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmessaging`: [v1.2.0](service/chimesdkmessaging/CHANGELOG.md#v120-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codegurureviewer`: [v1.7.0](service/codegurureviewer/CHANGELOG.md#v170-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.10.0](service/eks/CHANGELOG.md#v1100-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.11.0](service/elasticache/CHANGELOG.md#v1110-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/emr`: [v1.9.0](service/emr/CHANGELOG.md#v190-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/forecast`: [v1.10.0](service/forecast/CHANGELOG.md#v1100-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/frauddetector`: [v1.9.0](service/frauddetector/CHANGELOG.md#v190-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kafka`: [v1.7.0](service/kafka/CHANGELOG.md#v170-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lookoutequipment`: [v1.4.0](service/lookoutequipment/CHANGELOG.md#v140-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediapackage`: [v1.8.0](service/mediapackage/CHANGELOG.md#v180-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/opensearch`: [v1.0.0](service/opensearch/CHANGELOG.md#v100-2021-09-10)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.8.0](service/outposts/CHANGELOG.md#v180-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ram`: [v1.7.0](service/ram/CHANGELOG.md#v170-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.14.0](service/sagemaker/CHANGELOG.md#v1140-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/servicediscovery`: [v1.9.0](service/servicediscovery/CHANGELOG.md#v190-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssmcontacts`: [v1.5.0](service/ssmcontacts/CHANGELOG.md#v150-2021-09-10)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/xray`: [v1.6.0](service/xray/CHANGELOG.md#v160-2021-09-10)
  * **Feature**: API client updated

# Release (2021-09-02)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/config`: [v1.8.0](config/CHANGELOG.md#v180-2021-09-02)
  * **Feature**: Add support for S3 Multi-Region Access Point ARNs.
* `github.com/aws/aws-sdk-go-v2/service/accessanalyzer`: [v1.7.0](service/accessanalyzer/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/acmpca`: [v1.8.0](service/acmpca/CHANGELOG.md#v180-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloud9`: [v1.8.0](service/cloud9/CHANGELOG.md#v180-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.10.0](service/cloudformation/CHANGELOG.md#v1100-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudtrail`: [v1.6.0](service/cloudtrail/CHANGELOG.md#v160-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.10.0](service/codebuild/CHANGELOG.md#v1100-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.9.0](service/computeoptimizer/CHANGELOG.md#v190-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/configservice`: [v1.9.0](service/configservice/CHANGELOG.md#v190-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ebs`: [v1.7.0](service/ebs/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.16.0](service/ec2/CHANGELOG.md#v1160-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/efs`: [v1.7.0](service/efs/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/emr`: [v1.8.0](service/emr/CHANGELOG.md#v180-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/firehose`: [v1.6.0](service/firehose/CHANGELOG.md#v160-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/frauddetector`: [v1.8.0](service/frauddetector/CHANGELOG.md#v180-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.9.0](service/fsx/CHANGELOG.md#v190-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/internal/s3shared`: [v1.7.0](service/internal/s3shared/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: Add support for S3 Multi-Region Access Point ARNs.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.11.0](service/iot/CHANGELOG.md#v1110-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotjobsdataplane`: [v1.5.0](service/iotjobsdataplane/CHANGELOG.md#v150-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ivs`: [v1.7.0](service/ivs/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.6.0](service/kms/CHANGELOG.md#v160-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelbuildingservice`: [v1.9.0](service/lexmodelbuildingservice/CHANGELOG.md#v190-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediatailor`: [v1.7.0](service/mediatailor/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/memorydb`: [v1.2.0](service/memorydb/CHANGELOG.md#v120-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mwaa`: [v1.5.0](service/mwaa/CHANGELOG.md#v150-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/polly`: [v1.6.0](service/polly/CHANGELOG.md#v160-2021-09-02)
  * **Feature**: API client updated
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.10.0](service/quicksight/CHANGELOG.md#v1100-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.15.0](service/s3/CHANGELOG.md#v1150-2021-09-02)
  * **Feature**: API client updated
  * **Feature**: Add support for S3 Multi-Region Access Point ARNs.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.11.0](service/s3control/CHANGELOG.md#v1110-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemakerruntime`: [v1.7.0](service/sagemakerruntime/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/schemas`: [v1.6.0](service/schemas/CHANGELOG.md#v160-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.10.0](service/securityhub/CHANGELOG.md#v1100-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/servicecatalogappregistry`: [v1.5.0](service/servicecatalogappregistry/CHANGELOG.md#v150-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.9.0](service/sqs/CHANGELOG.md#v190-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssmincidents`: [v1.4.0](service/ssmincidents/CHANGELOG.md#v140-2021-09-02)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.7.0](service/transfer/CHANGELOG.md#v170-2021-09-02)
  * **Feature**: API client updated

# Release (2021-08-27)

## General Highlights
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/credentials`: [v1.4.0](credentials/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Adds support for Tags and TransitiveTagKeys to stscreds.AssumeRoleProvider. Closes https://github.com/aws/aws-sdk-go-v2/issues/723
* `github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue`: [v1.2.0](feature/dynamodb/attributevalue/CHANGELOG.md#v120-2021-08-27)
  * **Bug Fix**: Fix unmarshaler's decoding of AttributeValueMemberN into a type that is a string alias.
* `github.com/aws/aws-sdk-go-v2/service/acmpca`: [v1.7.0](service/acmpca/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/amplify`: [v1.5.0](service/amplify/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/amplifybackend`: [v1.4.0](service/amplifybackend/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/apigateway`: [v1.7.0](service/apigateway/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi`: [v1.4.0](service/apigatewaymanagementapi/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/appflow`: [v1.7.0](service/appflow/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/applicationinsights`: [v1.4.0](service/applicationinsights/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/apprunner`: [v1.2.0](service/apprunner/CHANGELOG.md#v120-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/appstream`: [v1.6.0](service/appstream/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/appsync`: [v1.6.0](service/appsync/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/athena`: [v1.6.0](service/athena/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/auditmanager`: [v1.8.0](service/auditmanager/CHANGELOG.md#v180-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/autoscalingplans`: [v1.5.0](service/autoscalingplans/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/backup`: [v1.5.0](service/backup/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/batch`: [v1.7.0](service/batch/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/braket`: [v1.6.0](service/braket/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/chimesdkidentity`: [v1.1.0](service/chimesdkidentity/CHANGELOG.md#v110-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmessaging`: [v1.1.0](service/chimesdkmessaging/CHANGELOG.md#v110-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/cloudtrail`: [v1.5.0](service/cloudtrail/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchevents`: [v1.6.0](service/cloudwatchevents/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/codeartifact`: [v1.5.0](service/codeartifact/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.9.0](service/codebuild/CHANGELOG.md#v190-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/codecommit`: [v1.4.0](service/codecommit/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/codeguruprofiler`: [v1.5.0](service/codeguruprofiler/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/codestarnotifications`: [v1.4.0](service/codestarnotifications/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentity`: [v1.5.0](service/cognitoidentity/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider`: [v1.6.0](service/cognitoidentityprovider/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/comprehend`: [v1.6.0](service/comprehend/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.8.0](service/computeoptimizer/CHANGELOG.md#v180-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/connectcontactlens`: [v1.5.0](service/connectcontactlens/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/customerprofiles`: [v1.9.0](service/customerprofiles/CHANGELOG.md#v190-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.7.0](service/databasemigrationservice/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/datasync`: [v1.6.0](service/datasync/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/dax`: [v1.4.0](service/dax/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/directoryservice`: [v1.5.0](service/directoryservice/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/dlm`: [v1.5.0](service/dlm/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/dynamodbstreams`: [v1.4.0](service/dynamodbstreams/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.15.0](service/ec2/CHANGELOG.md#v1150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ecrpublic`: [v1.5.0](service/ecrpublic/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/efs`: [v1.6.0](service/efs/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.9.0](service/eks/CHANGELOG.md#v190-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/emrcontainers`: [v1.6.0](service/emrcontainers/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/eventbridge`: [v1.7.0](service/eventbridge/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/finspace`: [v1.2.0](service/finspace/CHANGELOG.md#v120-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/finspacedata`: [v1.2.0](service/finspacedata/CHANGELOG.md#v120-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/firehose`: [v1.5.0](service/firehose/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/fms`: [v1.7.0](service/fms/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/forecast`: [v1.9.0](service/forecast/CHANGELOG.md#v190-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/forecastquery`: [v1.4.0](service/forecastquery/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/frauddetector`: [v1.7.0](service/frauddetector/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.8.0](service/fsx/CHANGELOG.md#v180-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/gamelift`: [v1.6.0](service/gamelift/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.11.0](service/glue/CHANGELOG.md#v1110-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/groundstation`: [v1.6.0](service/groundstation/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/guardduty`: [v1.5.0](service/guardduty/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/health`: [v1.7.0](service/health/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/healthlake`: [v1.6.0](service/healthlake/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.10.0](service/iot/CHANGELOG.md#v1100-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iot1clickdevicesservice`: [v1.4.0](service/iot1clickdevicesservice/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iotanalytics`: [v1.5.0](service/iotanalytics/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iotdataplane`: [v1.4.0](service/iotdataplane/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iotfleethub`: [v1.5.0](service/iotfleethub/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.11.0](service/iotsitewise/CHANGELOG.md#v1110-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ivs`: [v1.6.0](service/ivs/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lakeformation`: [v1.5.0](service/lakeformation/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.6.0](service/lexmodelsv2/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.3.0](service/lexruntimev2/CHANGELOG.md#v130-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/licensemanager`: [v1.7.0](service/licensemanager/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.10.0](service/lightsail/CHANGELOG.md#v1100-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lookoutequipment`: [v1.3.0](service/lookoutequipment/CHANGELOG.md#v130-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/lookoutmetrics`: [v1.3.0](service/lookoutmetrics/CHANGELOG.md#v130-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.9.0](service/macie2/CHANGELOG.md#v190-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.10.0](service/mediaconvert/CHANGELOG.md#v1100-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mediapackage`: [v1.7.0](service/mediapackage/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mediapackagevod`: [v1.7.0](service/mediapackagevod/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mq`: [v1.5.0](service/mq/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/networkfirewall`: [v1.5.0](service/networkfirewall/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.7.0](service/outposts/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/pi`: [v1.6.0](service/pi/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/pinpointsmsvoice`: [v1.4.0](service/pinpointsmsvoice/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/polly`: [v1.5.0](service/polly/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/qldb`: [v1.6.0](service/qldb/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/qldbsession`: [v1.5.0](service/qldbsession/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ram`: [v1.6.0](service/ram/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/rekognition`: [v1.8.0](service/rekognition/CHANGELOG.md#v180-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi`: [v1.5.0](service/resourcegroupstaggingapi/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/robomaker`: [v1.8.0](service/robomaker/CHANGELOG.md#v180-2021-08-27)
  * **Bug Fix**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/route53recoverycontrolconfig`: [v1.1.0](service/route53recoverycontrolconfig/CHANGELOG.md#v110-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/route53resolver`: [v1.7.0](service/route53resolver/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.14.0](service/s3/CHANGELOG.md#v1140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.10.0](service/s3control/CHANGELOG.md#v1100-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/s3outposts`: [v1.5.0](service/s3outposts/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/servicecatalog`: [v1.5.0](service/servicecatalog/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/servicecatalogappregistry`: [v1.4.0](service/servicecatalogappregistry/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/signer`: [v1.5.0](service/signer/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/ssooidc`: [v1.4.0](service/ssooidc/CHANGELOG.md#v140-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/storagegateway`: [v1.6.0](service/storagegateway/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/synthetics`: [v1.6.0](service/synthetics/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/textract`: [v1.5.0](service/textract/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.7.0](service/transcribe/CHANGELOG.md#v170-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.6.0](service/transfer/CHANGELOG.md#v160-2021-08-27)
  * **Feature**: Updated API model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/wafregional`: [v1.5.0](service/wafregional/CHANGELOG.md#v150-2021-08-27)
  * **Feature**: Updated API model to latest revision.

# Release (2021-08-19)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/apigateway`: [v1.6.0](service/apigateway/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/apigatewayv2`: [v1.5.0](service/apigatewayv2/CHANGELOG.md#v150-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appflow`: [v1.6.0](service/appflow/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/applicationautoscaling`: [v1.5.0](service/applicationautoscaling/CHANGELOG.md#v150-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloud9`: [v1.6.0](service/cloud9/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/clouddirectory`: [v1.4.0](service/clouddirectory/CHANGELOG.md#v140-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs`: [v1.6.0](service/cloudwatchlogs/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.8.0](service/codebuild/CHANGELOG.md#v180-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/configservice`: [v1.7.0](service/configservice/CHANGELOG.md#v170-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/costexplorer`: [v1.8.0](service/costexplorer/CHANGELOG.md#v180-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/customerprofiles`: [v1.8.0](service/customerprofiles/CHANGELOG.md#v180-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databrew`: [v1.8.0](service/databrew/CHANGELOG.md#v180-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/directoryservice`: [v1.4.0](service/directoryservice/CHANGELOG.md#v140-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.14.0](service/ec2/CHANGELOG.md#v1140-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.9.0](service/elasticache/CHANGELOG.md#v190-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/emr`: [v1.6.0](service/emr/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.10.0](service/iotsitewise/CHANGELOG.md#v1100-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.7.0](service/lambda/CHANGELOG.md#v170-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/licensemanager`: [v1.6.0](service/licensemanager/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/memorydb`: [v1.0.0](service/memorydb/CHANGELOG.md#v100-2021-08-19)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.8.0](service/quicksight/CHANGELOG.md#v180-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.10.0](service/route53/CHANGELOG.md#v1100-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/route53resolver`: [v1.6.0](service/route53resolver/CHANGELOG.md#v160-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.13.0](service/s3/CHANGELOG.md#v1130-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.12.0](service/sagemaker/CHANGELOG.md#v1120-2021-08-19)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemakerruntime`: [v1.5.0](service/sagemakerruntime/CHANGELOG.md#v150-2021-08-19)
  * **Feature**: API client updated

# Release (2021-08-12)

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign`: [v1.3.1](feature/cloudfront/sign/CHANGELOG.md#v131-2021-08-12)
  * **Bug Fix**: Update to not escape HTML when encoding the policy.
* `github.com/aws/aws-sdk-go-v2/service/athena`: [v1.5.0](service/athena/CHANGELOG.md#v150-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.11.0](service/autoscaling/CHANGELOG.md#v1110-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.8.0](service/chime/CHANGELOG.md#v180-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkidentity`: [v1.0.0](service/chimesdkidentity/CHANGELOG.md#v100-2021-08-12)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chimesdkmessaging`: [v1.0.0](service/chimesdkmessaging/CHANGELOG.md#v100-2021-08-12)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.7.0](service/codebuild/CHANGELOG.md#v170-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.6.0](service/connect/CHANGELOG.md#v160-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ebs`: [v1.5.0](service/ebs/CHANGELOG.md#v150-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.8.0](service/ecs/CHANGELOG.md#v180-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.5.0](service/lexmodelsv2/CHANGELOG.md#v150-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.9.0](service/lightsail/CHANGELOG.md#v190-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/nimble`: [v1.3.0](service/nimble/CHANGELOG.md#v130-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rekognition`: [v1.7.0](service/rekognition/CHANGELOG.md#v170-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.9.0](service/route53/CHANGELOG.md#v190-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/snowdevicemanagement`: [v1.0.0](service/snowdevicemanagement/CHANGELOG.md#v100-2021-08-12)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.9.0](service/ssm/CHANGELOG.md#v190-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/synthetics`: [v1.5.0](service/synthetics/CHANGELOG.md#v150-2021-08-12)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.7.0](service/wafv2/CHANGELOG.md#v170-2021-08-12)
  * **Feature**: API client updated

# Release (2021-08-04)

## General Highlights
* **Feature**: adds error handling for defered close calls
* **Dependency Update**: Updated `github.com/aws/smithy-go` to latest version.
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.8.0
  * **Bug Fix**: Corrected an issue where the retryer was not using the last attempt's ResultMetadata as the bases for the return result from the stack. ([#1345](https://github.com/aws/aws-sdk-go-v2/pull/1345))
* `github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression`: [v1.2.0](feature/dynamodb/expression/CHANGELOG.md#v120-2021-08-04)
  * **Feature**: Add IsSet helper for ConditionBuilder and KeyConditionBuilder ([#1329](https://github.com/aws/aws-sdk-go-v2/pull/1329))
* `github.com/aws/aws-sdk-go-v2/service/accessanalyzer`: [v1.5.2](service/accessanalyzer/CHANGELOG.md#v152-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/amp`: [v1.3.1](service/amp/CHANGELOG.md#v131-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/appintegrations`: [v1.5.0](service/appintegrations/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/appmesh`: [v1.4.2](service/appmesh/CHANGELOG.md#v142-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/appsync`: [v1.5.0](service/appsync/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/auditmanager`: [v1.7.0](service/auditmanager/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/batch`: [v1.6.0](service/batch/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/braket`: [v1.5.2](service/braket/CHANGELOG.md#v152-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.7.0](service/chime/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.8.0](service/cloudformation/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudwatch`: [v1.7.0](service/cloudwatch/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.6.0](service/codebuild/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/codeguruprofiler`: [v1.4.2](service/codeguruprofiler/CHANGELOG.md#v142-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider`: [v1.5.0](service/cognitoidentityprovider/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.7.0](service/computeoptimizer/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/databrew`: [v1.7.0](service/databrew/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/directconnect`: [v1.7.0](service/directconnect/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.13.0](service/ec2/CHANGELOG.md#v1130-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.7.0](service/ecs/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.6.0](service/elasticloadbalancingv2/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/emr`: [v1.5.0](service/emr/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/emrcontainers`: [v1.5.0](service/emrcontainers/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/eventbridge`: [v1.6.0](service/eventbridge/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.10.0](service/glue/CHANGELOG.md#v1100-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/greengrassv2`: [v1.5.0](service/greengrassv2/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/groundstation`: [v1.5.2](service/groundstation/CHANGELOG.md#v152-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.8.0](service/iam/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/identitystore`: [v1.4.0](service/identitystore/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.8.0](service/imagebuilder/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.9.0](service/iot/CHANGELOG.md#v190-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotanalytics`: [v1.4.0](service/iotanalytics/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.9.0](service/iotsitewise/CHANGELOG.md#v190-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotwireless`: [v1.8.0](service/iotwireless/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.10.0](service/kendra/CHANGELOG.md#v1100-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.6.0](service/lambda/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/lexmodelbuildingservice`: [v1.7.0](service/lexmodelbuildingservice/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.4.0](service/lexmodelsv2/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/location`: [v1.4.0](service/location/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.9.0](service/mediaconvert/CHANGELOG.md#v190-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/medialive`: [v1.8.0](service/medialive/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/mgn`: [v1.3.1](service/mgn/CHANGELOG.md#v131-2021-08-04)
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/personalize`: [v1.7.0](service/personalize/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/proton`: [v1.2.0](service/proton/CHANGELOG.md#v120-2021-08-04)
  * **Feature**: Updated to latest API model.
  * **Bug Fix**: Fixed an issue that caused one or more API operations to fail when attempting to resolve the service endpoint. ([#1349](https://github.com/aws/aws-sdk-go-v2/pull/1349))
* `github.com/aws/aws-sdk-go-v2/service/qldb`: [v1.5.0](service/qldb/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.7.0](service/quicksight/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.7.0](service/rds/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.10.0](service/redshift/CHANGELOG.md#v1100-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/redshiftdata`: [v1.5.0](service/redshiftdata/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/robomaker`: [v1.7.0](service/robomaker/CHANGELOG.md#v170-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.8.0](service/route53/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53recoverycluster`: [v1.0.0](service/route53recoverycluster/CHANGELOG.md#v100-2021-08-04)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53recoverycontrolconfig`: [v1.0.0](service/route53recoverycontrolconfig/CHANGELOG.md#v100-2021-08-04)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53recoveryreadiness`: [v1.0.0](service/route53recoveryreadiness/CHANGELOG.md#v100-2021-08-04)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.12.0](service/s3/CHANGELOG.md#v1120-2021-08-04)
  * **Feature**: Add `HeadObject` presign support. ([#1346](https://github.com/aws/aws-sdk-go-v2/pull/1346))
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.9.0](service/s3control/CHANGELOG.md#v190-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3outposts`: [v1.4.0](service/s3outposts/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.11.0](service/sagemaker/CHANGELOG.md#v1110-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/secretsmanager`: [v1.5.0](service/secretsmanager/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.8.0](service/securityhub/CHANGELOG.md#v180-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/shield`: [v1.6.0](service/shield/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssmcontacts`: [v1.3.0](service/ssmcontacts/CHANGELOG.md#v130-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssmincidents`: [v1.2.0](service/ssmincidents/CHANGELOG.md#v120-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssoadmin`: [v1.5.0](service/ssoadmin/CHANGELOG.md#v150-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/synthetics`: [v1.4.0](service/synthetics/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/textract`: [v1.4.0](service/textract/CHANGELOG.md#v140-2021-08-04)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.6.0](service/transcribe/CHANGELOG.md#v160-2021-08-04)
  * **Feature**: Updated to latest API model.

# Release (2021-07-15)

## General Highlights
* **Dependency Update**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/config`: [v1.5.0](config/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Support has been added for EC2 IPv6-enabled Instance Metadata Service Endpoints.
* `github.com/aws/aws-sdk-go-v2/feature/ec2/imds`: [v1.3.0](feature/ec2/imds/CHANGELOG.md#v130-2021-07-15)
  * **Feature**: Support has been added for EC2 IPv6-enabled Instance Metadata Service Endpoints.
* `github.com/aws/aws-sdk-go-v2/service/acm`: [v1.5.0](service/acm/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/amp`: [v1.3.0](service/amp/CHANGELOG.md#v130-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/amplify`: [v1.4.0](service/amplify/CHANGELOG.md#v140-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/amplifybackend`: [v1.3.0](service/amplifybackend/CHANGELOG.md#v130-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.10.0](service/autoscaling/CHANGELOG.md#v1100-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.6.0](service/chime/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.7.0](service/cloudformation/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudfront`: [v1.7.0](service/cloudfront/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/cloudsearch`: [v1.5.0](service/cloudsearch/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudwatch`: [v1.6.0](service/cloudwatch/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/databasemigrationservice`: [v1.6.0](service/databasemigrationservice/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/devopsguru`: [v1.6.0](service/devopsguru/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/directconnect`: [v1.6.0](service/directconnect/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.8.0](service/docdb/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.12.0](service/ec2/CHANGELOG.md#v1120-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.8.0](service/eks/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.8.0](service/elasticache/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk`: [v1.5.0](service/elasticbeanstalk/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing`: [v1.5.0](service/elasticloadbalancing/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.5.0](service/elasticloadbalancingv2/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/fms`: [v1.6.0](service/fms/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/frauddetector`: [v1.6.0](service/frauddetector/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.9.0](service/glue/CHANGELOG.md#v190-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/health`: [v1.6.0](service/health/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/healthlake`: [v1.5.0](service/healthlake/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.7.0](service/iam/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.7.0](service/imagebuilder/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.8.0](service/iot/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.8.0](service/iotsitewise/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.9.0](service/kendra/CHANGELOG.md#v190-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/lambda`: [v1.5.0](service/lambda/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/lexmodelbuildingservice`: [v1.6.0](service/lexmodelbuildingservice/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.8.0](service/lightsail/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/macie`: [v1.5.1](service/macie/CHANGELOG.md#v151-2021-07-15)
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.8.1](service/macie2/CHANGELOG.md#v181-2021-07-15)
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.8.0](service/mediaconvert/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/mediatailor`: [v1.5.0](service/mediatailor/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/mgn`: [v1.3.0](service/mgn/CHANGELOG.md#v130-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/mq`: [v1.4.0](service/mq/CHANGELOG.md#v140-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.7.0](service/neptune/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.6.0](service/outposts/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/pricing`: [v1.5.1](service/pricing/CHANGELOG.md#v151-2021-07-15)
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.6.0](service/rds/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.9.0](service/redshift/CHANGELOG.md#v190-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.10.0](service/sagemaker/CHANGELOG.md#v1100-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/ses`: [v1.5.0](service/ses/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/sns`: [v1.7.0](service/sns/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.7.0](service/sqs/CHANGELOG.md#v170-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.8.0](service/ssm/CHANGELOG.md#v180-2021-07-15)
  * **Feature**: Updated service model to latest version.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/storagegateway`: [v1.5.0](service/storagegateway/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.
* `github.com/aws/aws-sdk-go-v2/service/sts`: [v1.6.0](service/sts/CHANGELOG.md#v160-2021-07-15)
  * **Feature**: The ErrorCode method on generated service error types has been corrected to match the API model.
  * **Documentation**: Updated service model to latest revision.
* `github.com/aws/aws-sdk-go-v2/service/wellarchitected`: [v1.5.0](service/wellarchitected/CHANGELOG.md#v150-2021-07-15)
  * **Feature**: Updated service model to latest version.

# Release (2021-07-01)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/internal/ini`: [v1.1.0](internal/ini/CHANGELOG.md#v110-2021-07-01)
  * **Feature**: Support for `:`, `=`, `[`, `]` being present in expression values.
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.9.0](service/autoscaling/CHANGELOG.md#v190-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/databrew`: [v1.6.0](service/databrew/CHANGELOG.md#v160-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.11.0](service/ec2/CHANGELOG.md#v1110-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.8.0](service/glue/CHANGELOG.md#v180-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.8.0](service/kendra/CHANGELOG.md#v180-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.7.0](service/mediaconvert/CHANGELOG.md#v170-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediapackagevod`: [v1.6.0](service/mediapackagevod/CHANGELOG.md#v160-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.8.0](service/redshift/CHANGELOG.md#v180-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.9.0](service/sagemaker/CHANGELOG.md#v190-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/servicediscovery`: [v1.7.0](service/servicediscovery/CHANGELOG.md#v170-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.6.0](service/sqs/CHANGELOG.md#v160-2021-07-01)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssmcontacts`: [v1.2.0](service/ssmcontacts/CHANGELOG.md#v120-2021-07-01)
  * **Feature**: API client updated

# Release (2021-06-25)

## General Highlights
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.7.0
  * **Feature**: Adds configuration values for enabling endpoint discovery.
  * **Bug Fix**: Keep Object-Lock headers a header when presigning Sigv4 signing requests
* `github.com/aws/aws-sdk-go-v2/config`: [v1.4.0](config/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: Adds configuration setting for enabling endpoint discovery.
* `github.com/aws/aws-sdk-go-v2/credentials`: [v1.3.0](credentials/CHANGELOG.md#v130-2021-06-25)
  * **Bug Fix**: Fixed example usages of aws.CredentialsCache ([#1275](https://github.com/aws/aws-sdk-go-v2/pull/1275))
* `github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign`: [v1.2.0](feature/cloudfront/sign/CHANGELOG.md#v120-2021-06-25)
  * **Feature**: Add UnmarshalJSON for AWSEpochTime to correctly unmarshal AWSEpochTime, ([#1298](https://github.com/aws/aws-sdk-go-v2/pull/1298))
* `github.com/aws/aws-sdk-go-v2/internal/configsources`: [v1.0.0](internal/configsources/CHANGELOG.md#v100-2021-06-25)
  * **Release**: Release new modules
* `github.com/aws/aws-sdk-go-v2/service/amp`: [v1.2.0](service/amp/CHANGELOG.md#v120-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/amplify`: [v1.3.0](service/amplify/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/amplifybackend`: [v1.2.0](service/amplifybackend/CHANGELOG.md#v120-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appflow`: [v1.5.0](service/appflow/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/appmesh`: [v1.4.0](service/appmesh/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/chime`: [v1.5.0](service/chime/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloud9`: [v1.5.0](service/cloud9/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudformation`: [v1.6.0](service/cloudformation/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudfront`: [v1.6.0](service/cloudfront/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudsearch`: [v1.4.0](service/cloudsearch/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatch`: [v1.5.0](service/cloudwatch/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchevents`: [v1.5.0](service/cloudwatchevents/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codebuild`: [v1.5.0](service/codebuild/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/codegurureviewer`: [v1.5.0](service/codegurureviewer/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentity`: [v1.4.0](service/cognitoidentity/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider`: [v1.4.0](service/cognitoidentityprovider/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.5.0](service/connect/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dax`: [v1.3.0](service/dax/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.7.0](service/docdb/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/dynamodb`: [v1.4.0](service/dynamodb/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: Adds support for endpoint discovery.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.10.0](service/ec2/CHANGELOG.md#v1100-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.7.0](service/elasticache/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk`: [v1.4.0](service/elasticbeanstalk/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing`: [v1.4.0](service/elasticloadbalancing/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`: [v1.4.0](service/elasticloadbalancingv2/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eventbridge`: [v1.5.0](service/eventbridge/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/greengrass`: [v1.5.0](service/greengrass/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/greengrassv2`: [v1.4.0](service/greengrassv2/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.6.0](service/iam/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery`: [v1.0.0](service/internal/endpoint-discovery/CHANGELOG.md#v100-2021-06-25)
  * **Release**: Release new modules
  * **Feature**: Module supporting endpoint-discovery across all service clients.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.7.0](service/iot/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotanalytics`: [v1.3.0](service/iotanalytics/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.7.0](service/kendra/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kms`: [v1.4.0](service/kms/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.3.0](service/lexmodelsv2/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexruntimev2`: [v1.2.0](service/lexruntimev2/CHANGELOG.md#v120-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/licensemanager`: [v1.5.0](service/licensemanager/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lookoutmetrics`: [v1.2.0](service/lookoutmetrics/CHANGELOG.md#v120-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/managedblockchain`: [v1.4.0](service/managedblockchain/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconnect`: [v1.6.0](service/mediaconnect/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/medialive`: [v1.7.0](service/medialive/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediatailor`: [v1.4.0](service/mediatailor/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.6.0](service/neptune/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/proton`: [v1.1.0](service/proton/CHANGELOG.md#v110-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.6.0](service/quicksight/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ram`: [v1.5.0](service/ram/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.5.0](service/rds/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshift`: [v1.7.0](service/redshift/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/redshiftdata`: [v1.4.0](service/redshiftdata/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.7.0](service/route53/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.8.0](service/sagemaker/CHANGELOG.md#v180-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemakerfeaturestoreruntime`: [v1.4.0](service/sagemakerfeaturestoreruntime/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.7.0](service/securityhub/CHANGELOG.md#v170-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ses`: [v1.4.0](service/ses/CHANGELOG.md#v140-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/snowball`: [v1.5.0](service/snowball/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sns`: [v1.6.0](service/sns/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.5.0](service/sqs/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sts`: [v1.5.0](service/sts/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/timestreamquery`: [v1.3.0](service/timestreamquery/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: Adds support for endpoint discovery.
* `github.com/aws/aws-sdk-go-v2/service/timestreamwrite`: [v1.3.0](service/timestreamwrite/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: Adds support for endpoint discovery.
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.5.0](service/transfer/CHANGELOG.md#v150-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/waf`: [v1.3.0](service/waf/CHANGELOG.md#v130-2021-06-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/wafv2`: [v1.6.0](service/wafv2/CHANGELOG.md#v160-2021-06-25)
  * **Feature**: API client updated

# Release (2021-06-11)

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.7.0](service/autoscaling/CHANGELOG.md#v170-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudtrail`: [v1.3.2](service/cloudtrail/CHANGELOG.md#v132-2021-06-11)
  * **Documentation**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider`: [v1.3.3](service/cognitoidentityprovider/CHANGELOG.md#v133-2021-06-11)
  * **Documentation**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.6.0](service/eks/CHANGELOG.md#v160-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.6.0](service/fsx/CHANGELOG.md#v160-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/glue`: [v1.6.0](service/glue/CHANGELOG.md#v160-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.6.0](service/kendra/CHANGELOG.md#v160-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.7.0](service/macie2/CHANGELOG.md#v170-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/medialive`: [v1.6.0](service/medialive/CHANGELOG.md#v160-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/pi`: [v1.4.0](service/pi/CHANGELOG.md#v140-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/proton`: [v1.0.0](service/proton/CHANGELOG.md#v100-2021-06-11)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/qldb`: [v1.3.1](service/qldb/CHANGELOG.md#v131-2021-06-11)
  * **Documentation**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/rds`: [v1.4.2](service/rds/CHANGELOG.md#v142-2021-06-11)
  * **Documentation**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.7.0](service/sagemaker/CHANGELOG.md#v170-2021-06-11)
  * **Feature**: Updated to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.4.1](service/transfer/CHANGELOG.md#v141-2021-06-11)
  * **Documentation**: Updated to latest API model.

# Release (2021-06-04)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/acmpca`: [v1.5.0](service/acmpca/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.6.0](service/autoscaling/CHANGELOG.md#v160-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/braket`: [v1.4.0](service/braket/CHANGELOG.md#v140-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/cloudfront`: [v1.5.2](service/cloudfront/CHANGELOG.md#v152-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/datasync`: [v1.4.0](service/datasync/CHANGELOG.md#v140-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/devicefarm`: [v1.3.0](service/devicefarm/CHANGELOG.md#v130-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/docdb`: [v1.6.0](service/docdb/CHANGELOG.md#v160-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.9.0](service/ec2/CHANGELOG.md#v190-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.5.0](service/ecs/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/forecast`: [v1.7.0](service/forecast/CHANGELOG.md#v170-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/fsx`: [v1.5.0](service/fsx/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.5.1](service/iam/CHANGELOG.md#v151-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/internal/s3shared`: [v1.4.0](service/internal/s3shared/CHANGELOG.md#v140-2021-06-04)
  * **Feature**: The handling of AccessPoint and Outpost ARNs have been updated.
* `github.com/aws/aws-sdk-go-v2/service/iotevents`: [v1.4.0](service/iotevents/CHANGELOG.md#v140-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ioteventsdata`: [v1.3.0](service/ioteventsdata/CHANGELOG.md#v130-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.6.0](service/iotsitewise/CHANGELOG.md#v160-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/iotwireless`: [v1.6.0](service/iotwireless/CHANGELOG.md#v160-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/kendra`: [v1.5.0](service/kendra/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.6.1](service/lightsail/CHANGELOG.md#v161-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/location`: [v1.2.0](service/location/CHANGELOG.md#v120-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/mwaa`: [v1.2.0](service/mwaa/CHANGELOG.md#v120-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/outposts`: [v1.4.0](service/outposts/CHANGELOG.md#v140-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/polly`: [v1.3.0](service/polly/CHANGELOG.md#v130-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/qldb`: [v1.3.0](service/qldb/CHANGELOG.md#v130-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/resourcegroups`: [v1.3.2](service/resourcegroups/CHANGELOG.md#v132-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.6.2](service/route53/CHANGELOG.md#v162-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/route53resolver`: [v1.4.2](service/route53resolver/CHANGELOG.md#v142-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.10.0](service/s3/CHANGELOG.md#v1100-2021-06-04)
  * **Feature**: The handling of AccessPoint and Outpost ARNs have been updated.
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.7.0](service/s3control/CHANGELOG.md#v170-2021-06-04)
  * **Feature**: The handling of AccessPoint and Outpost ARNs have been updated.
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/servicediscovery`: [v1.5.0](service/servicediscovery/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sns`: [v1.5.0](service/sns/CHANGELOG.md#v150-2021-06-04)
  * **Feature**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/sqs`: [v1.4.2](service/sqs/CHANGELOG.md#v142-2021-06-04)
  * **Documentation**: Updated service client to latest API model.
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.6.2](service/ssm/CHANGELOG.md#v162-2021-06-04)
  * **Documentation**: Updated service client to latest API model.

# Release (2021-05-25)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs`: [v1.4.0](service/cloudwatchlogs/CHANGELOG.md#v140-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/commander`: [v1.1.0](service/commander/CHANGELOG.md#v110-2021-05-25)
  * **Feature**: Deprecated module. The API client was incorrectly named. Use AWS Systems Manager Incident Manager (ssmincidents) instead.
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.5.0](service/computeoptimizer/CHANGELOG.md#v150-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/costexplorer`: [v1.6.0](service/costexplorer/CHANGELOG.md#v160-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.8.0](service/ec2/CHANGELOG.md#v180-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/efs`: [v1.4.0](service/efs/CHANGELOG.md#v140-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/forecast`: [v1.6.0](service/forecast/CHANGELOG.md#v160-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.6.0](service/iot/CHANGELOG.md#v160-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/opsworkscm`: [v1.4.0](service/opsworkscm/CHANGELOG.md#v140-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.5.0](service/quicksight/CHANGELOG.md#v150-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.9.0](service/s3/CHANGELOG.md#v190-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/ssmincidents`: [v1.0.0](service/ssmincidents/CHANGELOG.md#v100-2021-05-25)
  * **Release**: New AWS service client module
* `github.com/aws/aws-sdk-go-v2/service/transfer`: [v1.4.0](service/transfer/CHANGELOG.md#v140-2021-05-25)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/workspaces`: [v1.4.0](service/workspaces/CHANGELOG.md#v140-2021-05-25)
  * **Feature**: API client updated

# Release (2021-05-20)

## General Highlights
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.6.0
  * **Feature**: `internal/ini`: This package has been migrated to a separate module at `github.com/aws/aws-sdk-go-v2/internal/ini`.
* `github.com/aws/aws-sdk-go-v2/config`: [v1.3.0](config/CHANGELOG.md#v130-2021-05-20)
  * **Feature**: SSO credentials can now be defined alongside other credential providers within the same configuration profile.
  * **Bug Fix**: Profile names were incorrectly normalized to lower-case, which could result in unexpected profile configurations.
* `github.com/aws/aws-sdk-go-v2/internal/ini`: [v1.0.0](internal/ini/CHANGELOG.md#v100-2021-05-20)
  * **Release**: The `github.com/aws/aws-sdk-go-v2/internal/ini` package is now a Go Module.
* `github.com/aws/aws-sdk-go-v2/service/applicationcostprofiler`: [v1.0.0](service/applicationcostprofiler/CHANGELOG.md#v100-2021-05-20)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/apprunner`: [v1.0.0](service/apprunner/CHANGELOG.md#v100-2021-05-20)
  * **Release**: New AWS service client module
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/autoscaling`: [v1.5.0](service/autoscaling/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/computeoptimizer`: [v1.4.0](service/computeoptimizer/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/detective`: [v1.6.0](service/detective/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.5.0](service/eks/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticache`: [v1.6.0](service/elasticache/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/elasticsearchservice`: [v1.4.0](service/elasticsearchservice/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iam`: [v1.5.0](service/iam/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/imagebuilder`: [v1.5.0](service/imagebuilder/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.5.0](service/iot/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotdeviceadvisor`: [v1.4.0](service/iotdeviceadvisor/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/iotsitewise`: [v1.5.0](service/iotsitewise/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesis`: [v1.4.0](service/kinesis/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesisanalytics`: [v1.3.0](service/kinesisanalytics/CHANGELOG.md#v130-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2`: [v1.4.0](service/kinesisanalyticsv2/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lexmodelsv2`: [v1.2.0](service/lexmodelsv2/CHANGELOG.md#v120-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/licensemanager`: [v1.4.0](service/licensemanager/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/lightsail`: [v1.6.0](service/lightsail/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/macie`: [v1.4.0](service/macie/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/macie2`: [v1.6.0](service/macie2/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/mediaconnect`: [v1.5.0](service/mediaconnect/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/neptune`: [v1.5.0](service/neptune/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/personalize`: [v1.5.0](service/personalize/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/quicksight`: [v1.4.0](service/quicksight/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/rekognition`: [v1.5.0](service/rekognition/CHANGELOG.md#v150-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.8.0](service/s3/CHANGELOG.md#v180-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemaker`: [v1.6.0](service/sagemaker/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/sagemakera2iruntime`: [v1.3.0](service/sagemakera2iruntime/CHANGELOG.md#v130-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/securityhub`: [v1.6.0](service/securityhub/CHANGELOG.md#v160-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/support`: [v1.3.0](service/support/CHANGELOG.md#v130-2021-05-20)
  * **Feature**: API client updated
* `github.com/aws/aws-sdk-go-v2/service/transcribe`: [v1.4.0](service/transcribe/CHANGELOG.md#v140-2021-05-20)
  * **Feature**: API client updated

# Release (2021-05-14)

## General Highlights
* **Feature**: Constant has been added to modules to enable runtime version inspection for reporting.
* **Dependency Update**: Updated to the latest SDK module versions

## Module Highlights
* `github.com/aws/aws-sdk-go-v2`: v1.5.0
  * **Feature**: `AddSDKAgentKey` and `AddSDKAgentKeyValue` in `aws/middleware` package have been updated to direct metadata to `User-Agent` HTTP header.
* `github.com/aws/aws-sdk-go-v2/service/codeartifact`: [v1.3.0](service/codeartifact/CHANGELOG.md#v130-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/commander`: [v1.0.0](service/commander/CHANGELOG.md#v100-2021-05-14)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/configservice`: [v1.5.0](service/configservice/CHANGELOG.md#v150-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/connect`: [v1.4.0](service/connect/CHANGELOG.md#v140-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/ec2`: [v1.7.0](service/ec2/CHANGELOG.md#v170-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/ecs`: [v1.4.0](service/ecs/CHANGELOG.md#v140-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/eks`: [v1.4.0](service/eks/CHANGELOG.md#v140-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/finspace`: [v1.0.0](service/finspace/CHANGELOG.md#v100-2021-05-14)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/finspacedata`: [v1.0.0](service/finspacedata/CHANGELOG.md#v100-2021-05-14)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/iot`: [v1.4.0](service/iot/CHANGELOG.md#v140-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/iotwireless`: [v1.5.0](service/iotwireless/CHANGELOG.md#v150-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/kinesis`: [v1.3.0](service/kinesis/CHANGELOG.md#v130-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/kinesisanalytics`: [v1.2.0](service/kinesisanalytics/CHANGELOG.md#v120-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2`: [v1.3.0](service/kinesisanalyticsv2/CHANGELOG.md#v130-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/lakeformation`: [v1.3.0](service/lakeformation/CHANGELOG.md#v130-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/lookoutmetrics`: [v1.1.0](service/lookoutmetrics/CHANGELOG.md#v110-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/mediaconvert`: [v1.5.0](service/mediaconvert/CHANGELOG.md#v150-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/route53`: [v1.6.0](service/route53/CHANGELOG.md#v160-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/s3`: [v1.7.0](service/s3/CHANGELOG.md#v170-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/s3control`: [v1.6.0](service/s3control/CHANGELOG.md#v160-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/ssm`: [v1.6.0](service/ssm/CHANGELOG.md#v160-2021-05-14)
  * **Feature**: Updated to latest service API model.
* `github.com/aws/aws-sdk-go-v2/service/ssmcontacts`: [v1.0.0](service/ssmcontacts/CHANGELOG.md#v100-2021-05-14)
  * **Release**: New AWS service client module
  * **Feature**: Updated to latest service API model.

# Release 2021-05-06

## Breaking change
* `service/ec2` - v1.6.0
  * This release contains a breaking change to the Amazon EC2 API client. API number(int/int64/etc) and boolean members were changed from value, to pointer type. Your applications using the EC2 API client will fail to compile after upgrading for all members that were updated. To migrate to this module you'll need to update your application to use pointers for all number and boolean members in the API client module. The SDK provides helper utilities to convert between value and pointer types. For example the [aws.Bool](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#Bool) function to get the address from a bool literal. Similar utilities are available for all other primitive types in the [aws](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws) package.

## Service Client Highlights
* `service/acmpca` - v1.3.0
  * Feature: API client updated
* `service/apigateway` - v1.3.0
  * Feature: API client updated
* `service/auditmanager` - v1.4.0
  * Feature: API client updated
* `service/chime` - v1.3.0
  * Feature: API client updated
* `service/cloudformation` - v1.4.0
  * Feature: API client updated
* `service/cloudfront` - v1.4.0
  * Feature: API client updated
* `service/codegurureviewer` - v1.3.0
  * Feature: API client updated
* `service/connect` - v1.3.0
  * Feature: API client updated
* `service/customerprofiles` - v1.5.0
  * Feature: API client updated
* `service/devopsguru` - v1.3.0
  * Feature: API client updated
* `service/docdb` - v1.4.0
  * Feature: API client updated
* `service/ec2` - v1.6.0
  * Bug Fix: Fix incorrectly modeled Amazon EC2 number and boolean members in structures. The Amazon EC2 API client has been updated with a breaking change to fix all structure number and boolean members to be pointer types instead of value types. Fixes [#1107](https://github.com/aws/aws-sdk-go-v2/issues/1107), [#1178](https://github.com/aws/aws-sdk-go-v2/issues/1178), and [#1190](https://github.com/aws/aws-sdk-go-v2/issues/1190). This breaking change is made within the major version of the client' module, because the client operations failed and were unusable with value type number and boolean members with the EC2 API.
  * Feature: API client updated
* `service/ecs` - v1.3.0
  * Feature: API client updated
* `service/eks` - v1.3.0
  * Feature: API client updated
* `service/forecast` - v1.4.0
  * Feature: API client updated
* `service/glue` - v1.4.0
  * Feature: API client updated
* `service/health` - v1.3.0
  * Feature: API client updated
* `service/iotsitewise` - v1.3.0
  * Feature: API client updated
* `service/iotwireless` - v1.4.0
  * Feature: API client updated
* `service/kafka` - v1.3.0
  * Feature: API client updated
* `service/kinesisanalyticsv2` - v1.2.0
  * Feature: API client updated
* `service/macie2` - v1.4.0
  * Feature: API client updated
* `service/marketplacecatalog` - v1.2.0
  * Feature: API client updated
* `service/mediaconvert` - v1.4.0
  * Feature: API client updated
* `service/mediapackage` - v1.4.0
  * Feature: API client updated
* `service/mediapackagevod` - v1.3.0
  * Feature: API client updated
* `service/mturk` - v1.2.0
  * Feature: API client updated
* `service/nimble` - v1.0.0
  * Feature: API client updated
* `service/organizations` - v1.3.0
  * Feature: API client updated
* `service/personalize` - v1.3.0
  * Feature: API client updated
* `service/robomaker` - v1.4.0
  * Feature: API client updated
* `service/route53` - v1.5.0
  * Feature: API client updated
* `service/s3` - v1.6.0
  * Bug Fix: Fix PutObject and UploadPart unseekable stream documentation link to point to the correct location.
  * Feature: API client updated
* `service/sagemaker` - v1.4.0
  * Feature: API client updated
* `service/securityhub` - v1.4.0
  * Feature: API client updated
* `service/servicediscovery` - v1.3.0
  * Feature: API client updated
* `service/snowball` - v1.3.0
  * Feature: API client updated
* `service/sns` - v1.3.0
  * Feature: API client updated
* `service/ssm` - v1.5.0
  * Feature: API client updated
## Core SDK Highlights
* Dependency Update: Update smithy-go dependency to v1.4.0
* Dependency Update: Updated SDK dependencies to their latest versions.
* `aws` - v1.4.0
  * Feature: Add support for FIPS global partition endpoints ([#1242](https://github.com/aws/aws-sdk-go-v2/pull/1242))

# Release 2021-04-23
## Service Client Highlights
* `service/cloudformation` - v1.3.2
  * Documentation: Service Documentation Updates
* `service/cognitoidentityprovider` - v1.2.3
  * Documentation: Service Documentation Updates
* `service/costexplorer` - v1.4.0
  * Feature: Service API Updates
* `service/databasemigrationservice` - v1.3.0
  * Feature: Service API Updates
* `service/detective` - v1.4.0
  * Feature: Service API Updates
* `service/elasticache` - v1.4.0
  * Feature: Service API Updates
* `service/forecast` - v1.3.0
  * Feature: Service API Updates
* `service/groundstation` - v1.3.0
  * Feature: Service API Updates
* `service/kendra` - v1.3.0
  * Feature: Service API Updates
* `service/redshift` - v1.5.0
  * Feature: Service API Updates
* `service/savingsplans` - v1.2.0
  * Feature: Service API Updates
* `service/securityhub` - v1.3.0
  * Feature: Service API Updates
## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.
* `feature/rds/auth` - v1.0.0
  * Feature: Add Support for Amazon RDS IAM Authentication

# Release 2021-04-14
## Service Client Highlights
* `service/codebuild` - v1.3.0
  * Feature: API client updated
* `service/codestarconnections` - v1.2.0
  * Feature: API client updated
* `service/comprehendmedical` - v1.2.0
  * Feature: API client updated
* `service/configservice` - v1.4.0
  * Feature: API client updated
* `service/ec2` - v1.5.0
  * Feature: API client updated
* `service/fsx` - v1.3.0
  * Feature: API client updated
* `service/lightsail` - v1.4.0
  * Feature: API client updated
* `service/mediaconnect` - v1.3.0
  * Feature: API client updated
* `service/rds` - v1.3.0
  * Feature: API client updated
* `service/redshift` - v1.4.0
  * Feature: API client updated
* `service/shield` - v1.3.0
  * Feature: API client updated
* `service/sts` - v1.3.0
  * Feature: API client updated
## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.

# Release 2021-04-08
## Service Client Highlights
* Feature: API model sync
* `service/lookoutequipment` - v1.0.0
  * v1 Release: new service client
* `service/mgn` - v1.0.0
  * v1 Release: new service client
## Core SDK Highlights
* Dependency Update: smithy-go version bump
* Dependency Update: Updated SDK dependencies to their latest versions.

# Release 2021-04-01
## Service Client Highlights
* Bug Fix: Fix URL Path and RawQuery of resolved endpoint being ignored by the API client's request serialization.
  * Fixes [issue#1191](https://github.com/aws/aws-sdk-go-v2/issues/1191)
* Refactored internal endpoints model for accessors
* Feature: updated to latest models
* New services 
  * `service/location` - v1.0.0
  * `service/lookoutmetrics` - v1.0.0
## Core SDK Highlights
* Dependency Update: update smithy-go module
* Dependency Update: Updated SDK dependencies to their latest versions.

# Release 2021-03-18
## Service Client Highlights
* Bug Fix: Updated presign URLs to no longer include the X-Amz-User-Agent header
* Feature: Update API model
* Add New supported API
* `service/internal/s3shared` - v1.2.0
  * Feature: Support for S3 Object Lambda
* `service/s3` - v1.3.0
  * Bug Fix: Adds documentation to the PutObject and UploadPart operations Body member how to upload unseekable objects to an Amazon S3 Bucket.
  * Feature: S3 Object Lambda is a new S3 feature that enables users to apply their own custom code to process the output of a standard S3 GET request by automatically invoking a Lambda function with a GET request
* `service/s3control` - v1.3.0
  * Feature: S3 Object Lambda is a new S3 feature that enables users to apply their own custom code to process the output of a standard S3 GET request by automatically invoking a Lambda function with a GET request
## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.
* `aws` - v1.3.0
  * Feature: Add helper to V4 signer package to swap compute payload hash middleware with unsigned payload middleware
* `feature/s3/manager` - v1.1.0
  * Bug Fix: Add support for Amazon S3 Object Lambda feature.
  * Feature: Updates for S3 Object Lambda feature

# Release 2021-03-12
## Service Client Highlights
* Bug Fix: Fixed a bug that could union shape types to be deserialized incorrectly
* Bug Fix: Fixed a bug where unboxed shapes that were marked as required were not serialized and sent over the wire, causing an API error from the service.
* Bug Fix: Fixed a bug with generated API Paginators' handling of nil input parameters causing a panic.
* Dependency Update: update smithy-go dependency
* `service/detective` - v1.1.2
  * Bug Fix: Fix deserialization of API response timestamp member.
* `service/docdb` - v1.2.0
  * Feature: Client now support presigned URL generation for CopyDBClusterSnapshot and CreateDBCluster operations by specifying the target SourceRegion
* `service/neptune` - v1.2.0
  * Feature: Client now support presigned URL generation for CopyDBClusterSnapshot and CreateDBCluster operations by specifying the target SourceRegion
* `service/s3` - v1.2.1
  * Bug Fix: Fixed an issue where ListObjectsV2 and ListParts paginators could loop infinitely
  * Bug Fix: Fixed key encoding when addressing S3 Access Points
## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.
* `config` - v1.1.2
  * Bug Fix: Fixed a panic when using WithEC2IMDSRegion without a specified IMDS client

# Release 2021-02-09
## Service Client Highlights
* `service/s3` - v1.2.0
  * Feature: adds support for s3 vpc endpoint interface [#1113](https://github.com/aws/aws-sdk-go-v2/pull/1113)
* `service/s3control` - v1.2.0
  * Feature: adds support for s3 vpc endpoint interface [#1113](https://github.com/aws/aws-sdk-go-v2/pull/1113)
## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.
* `aws` - v1.2.0
  * Feature: support to add endpoint source on context. Adds getter/setter for the endpoint source [#1113](https://github.com/aws/aws-sdk-go-v2/pull/1113)
* `config` - v1.1.1
  * Bug Fix: Only Validate SSO profile configuration when attempting to use SSO credentials [#1103](https://github.com/aws/aws-sdk-go-v2/pull/1103)
  * Bug Fix: Environment credentials were not taking precedence over AWS_PROFILE [#1103](https://github.com/aws/aws-sdk-go-v2/pull/1103)

# Release 2021-01-29
## Service Client Highlights
* Bug Fix: A serialization bug has been fixed that caused some service operations with empty inputs to not be serialized correctly ([#1071](https://github.com/aws/aws-sdk-go-v2/pull/1071))
* Bug Fix: Fixes a bug that could cause a waiter to fail when comparing types ([#1083](https://github.com/aws/aws-sdk-go-v2/pull/1083))
## Core SDK Highlights
* Feature: EndpointResolverFromURL helpers have been added for constructing a service EndpointResolver type ([#1066](https://github.com/aws/aws-sdk-go-v2/pull/1066))
* Dependency Update: Updated SDK dependencies to their latest versions.
* `aws` - v1.1.0
  * Feature: Add support for specifying the EndpointSource on aws.Endpoint types ([#1070](https://github.com/aws/aws-sdk-go-v2/pull/1070/))
* `config` - v1.1.0
  * Feature: Add Support for AWS Single Sign-On (SSO) credential provider ([#1072](https://github.com/aws/aws-sdk-go-v2/pull/1072))
* `credentials` - v1.1.0
  * Feature: Add AWS Single Sign-On (SSO) credential provider ([#1072](https://github.com/aws/aws-sdk-go-v2/pull/1072))

# Release 2021-01-19

We are excited to announce the [General Availability](https://aws.amazon.com/blogs/developer/aws-sdk-for-go-version-2-general-availability/)
(GA) release of the [AWS SDK for Go version 2 (v2)](https://github.com/aws/aws-sdk-go-v2).
This release follows the [Release candidate](https://aws.amazon.com/blogs/developer/aws-sdk-for-go-version-2-v2-release-candidate)
of the AWS SDK for Go v2. Version 2 incorporates customer feedback from version 1 and takes advantage of modern Go language features.

## Breaking Changes
* `aws`: Updated Config.Retryer member to be a func that returns aws.Retryer ([#1033](https://github.com/aws/aws-sdk-go-v2/pull/1033))
    * Updates the SDK's references to Config.Retryer to be a function that returns aws.Retryer value. This ensures that custom retry options specified in the `aws.Config` are scoped to individual client instances. 
    * All API clients created with the config will call the `Config.Retryer` function to get an aws.Retryer.
    * Removes duplicate `Retryer` interface from `retry` package. Single definition is `aws.Retryer` now.
* `aws/middleware`: Updates `AddAttemptClockSkewMiddleware` to use appropriate `AddRecordResponseTiming` naming ([#1031](https://github.com/aws/aws-sdk-go-v2/pull/1031))
    * Removes `ResponseMetadata` struct type, and adds its members to middleware metadata directly, to improve discoverability.
* `config`: Updated the `WithRetryer` helper to take a function that returns an aws.Retryer ([#1033](https://github.com/aws/aws-sdk-go-v2/pull/1033))
    * All API clients created with the config will call the `Config.Retryer` function to get an aws.Retryer.
* `API Clients`: Fix SDK's API client enum constant name generation to have expected casing ([#1020](https://github.com/aws/aws-sdk-go-v2/pull/1020))
    * This updates of the generated enum const value names in API client's `types` package to have the expected casing. Prior to this, enum names were being generated with lowercase names instead of camel case. 
* `API Clients`: Updates SDK's API client request middleware stack values to be scoped to individual operation call ([#1019](https://github.com/aws/aws-sdk-go-v2/pull/1019))
    * The API client request middleware stack values were mistakenly allowed to escape to nested API operation calls. This broke the SDK's presigners.
    * Stack values that should not escape are not scoped to the individual operation call.
* `Multiple API Clients`: Unexported the API client's `WithEndpointResolver` this type wasn't intended to be exported ([#1051](https://github.com/aws/aws-sdk-go-v2/pull/1051))
    * Using the `aws.Config.EndpointResolver` member for setting custom endpoint resolver instead.

## New Features
* `service/sts`: Add support for presigning GetCallerIdentity operation ([#1030](https://github.com/aws/aws-sdk-go-v2/pull/1030))
    * Adds a PresignClient to the `sts` API client module. Use PresignGetCallerIdentity to obtain presigned URLs for the create presigned URLs for the GetCallerIdentity operation.
    * Fixes [#1021](https://github.com/aws/aws-sdk-go-v2/issues/1021)
* `aws/retry`: Add package documentation for retry package ([#1033](https://github.com/aws/aws-sdk-go-v2/pull/1033))
    * Adds documentation for the retry package 

## Bug Fixes
* `Multiple API Clients`: Fix SDK's generated serde for unmodeled operation input/output ([#1050](https://github.com/aws/aws-sdk-go-v2/pull/1050))
    * Fixes [#1047](https://github.com/aws/aws-sdk-go-v2/issues/1047) by fixing the how the SDKs generated serialization and deserialization of API operations that did not have modeled input or output types. This caused the SDK to incorrectly attempt to deserialize response documents that were either empty, or contained unexpected data.
* `service/s3`: Fix Tagging parameter not serialized correctly for presigned PutObject requests ([#1017](https://github.com/aws/aws-sdk-go-v2/pull/1017))
    * Fixes the Tagging parameter incorrectly being serialized to the URL's query string instead of being signed as a HTTP request header.
    * When using PresignPutObject make sure to add all signed headers returned by the method to your down stream's HTTP client's request. These headers must be included in the request, or the request will fail with signature errors.
    * Fixes [#1016](https://github.com/aws/aws-sdk-go-v2/issues/1016)
* `service/s3`: Fix Unmarshaling `GetObjectAcl` operation's Grantee type response ([#1034](https://github.com/aws/aws-sdk-go-v2/pull/1034))
    * Updates the SDK's codegen for correctly deserializing XML attributes in tags with XML namespaces.
    * Fixes [#1013](https://github.com/aws/aws-sdk-go-v2/issues/1013)
* `service/s3`: Fix Unmarshaling `GetBucketLocation` operation's response ([#1027](https://github.com/aws/aws-sdk-go-v2/pull/1027))
    * Fixes [#908](https://github.com/aws/aws-sdk-go-v2/issues/908)

## Migrating from v2 preview SDK's v0.31.0 to v1.0.0

### aws.Config Retryer member

If your application sets the `Config.Retryer` member the application will need
to be updated to set a function that returns an `aws.Retryer`. In addition, if
your application used the `config.WithRetryer` helper a function that returns
an `aws.Retryer` needs to be used.

If your application used the `retry.Retryer` type, update to using the
`aws.Retryer` type instead.

### API Client enum value names

If your application used the enum values in the API Client's `types` package between v0.31.0 and the latest version of the client module you may need to update the naming of the enum value. The enum value name casing were updated to camel case instead lowercased.

# Release 2020-12-23

We’re happy to announce the Release Candidate (RC) of the AWS SDK for Go v2.
This RC follows the developer preview release of the AWS SDK for Go v2. The SDK
has undergone a major rewrite from the v1 code base to incorporate your
feedback and to take advantage of modern Go language features.

## Documentation
* Developer Guide: https://aws.github.io/aws-sdk-go-v2/docs/
* API Reference docs: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2
* Migration Guide: https://aws.github.io/aws-sdk-go-v2/docs/migrating/

## Breaking Changes
* Dependency `github.com/awslabs/smithy-go` has been relocated to `github.com/aws/smithy-go`
    * The `smithy-go` repository was moved from the `awslabs` GitHub organization to `aws`.
    * `xml`, `httpbinding`, and `json` package relocated under `encoding` package.
* The module `ec2imds` moved to `feature/ec2/imds` path ([#984](https://github.com/aws/aws-sdk-go-v2/pull/984))
    * Moves the `ec2imds` feature module to be in common location as other SDK features.
* `aws/signer/v4`: Refactor AWS Sigv4 Signer and options types to allow function options ([#955](https://github.com/aws/aws-sdk-go-v2/pull/955))
    * Fixes [#917](https://github.com/aws/aws-sdk-go-v2/issues/917), [#960](https://github.com/aws/aws-sdk-go-v2/issues/960), [#958](https://github.com/aws/aws-sdk-go-v2/issues/958)
* `aws`: CredentialCache type updated to require constructor function ([#946](https://github.com/aws/aws-sdk-go-v2/pull/946))
    * Fixes [#940](https://github.com/aws/aws-sdk-go-v2/issues/940)
* `credentials`: ExpiryWindow and Jitter moved from credential provider to `CredentialCache` ([#946](https://github.com/aws/aws-sdk-go-v2/pull/946))
    * Moves ExpiryWindow and Jitter options to common option of the `CredentialCache` instead of duplicated across providers.
    * Fixes [#940](https://github.com/aws/aws-sdk-go-v2/issues/940)
* `config`: Ensure shared credentials file has precedence over shared config file ([#990](https://github.com/aws/aws-sdk-go-v2/pull/990))
    * The shared config file was incorrectly overriding the shared credentials file when merging values.
* `config`: Add `context.Context` to `LoadDefaultConfig` ([#951](https://github.com/aws/aws-sdk-go-v2/pull/951))
    * Updates `config#LoadDefaultConfig` function to take `context.Context` as well as functional options for the `config#LoadOptions` type.
    * Fixes [#926](https://github.com/aws/aws-sdk-go-v2/issues/926), [#819](https://github.com/aws/aws-sdk-go-v2/issues/819)
* `aws`: Rename `NoOpRetryer` to `NopRetryer` to have consistent naming with rest of SDK ([#987](https://github.com/aws/aws-sdk-go-v2/pull/987))
    * Fixes [#878](https://github.com/aws/aws-sdk-go-v2/issues/878)
* `service/s3control`: Change `S3InitiateRestoreObjectOperation.ExpirationInDays` from value to pointer type ([#988](https://github.com/aws/aws-sdk-go-v2/pull/988))
* `aws`: `ReaderSeekerCloser` and `WriteAtBuffer` have been relocated to `feature/s3/manager`.

## New Features
* *Waiters*: Add Waiter utilities for API clients ([aws/smithy-go#237](https://github.com/aws/smithy-go/pull/237))
    * Your application can now use Waiter utilities to wait for AWS resources.
* `feature/dynamodb/attributevalue`: Add Amazon DynamoDB Attribute value marshaler utility ([#948](https://github.com/aws/aws-sdk-go-v2/pull/948))
    * Adds a utility for marshaling Go types too and from Amazon DynamoDB AttributeValues.
    * Also includes utility for converting from Amazon DynamoDB Streams AttributeValues to Amazon DynamoDB AttributeValues.
* `feature/dynamodbstreams/attributevalue`: Add Amazon DynamoDB Streams Attribute value marshaler utility ([#948](https://github.com/aws/aws-sdk-go-v2/pull/948))
    * Adds a utility for marshaling Go types too and from Amazon DynamoDB Streams AttributeValues.
    * Also includes utility for converting from Amazon DynamoDB AttributeValues to Amazon DynamoDB Streams AttributeValues.
* `feature/dynamodb/expression`: Add Amazon DynamoDB expression utility ([#981](https://github.com/aws/aws-sdk-go-v2/pull/981))
    * Adds the expression utility to the SDK for easily building Amazon DynamoDB operation expressions in code.

## Bug Fixes
* `service/s3`: Fix Presigner to configure client correctly for Amazon S3 ([#969](https://github.com/aws/aws-sdk-go-v2/pull/969))
* service/s3: Fix deserialization of CompleteMultipartUpload ([#965](https://github.com/aws/aws-sdk-go-v2/pull/965)
    * Fixes [#927](https://github.com/aws/aws-sdk-go-v2/issues/927)
* `codegen`: Fix API client union serialization ([#979](https://github.com/aws/aws-sdk-go-v2/pull/979))
    * Fixes [#978](https://github.com/aws/aws-sdk-go-v2/issues/978)

## Service Client Highlights
* API Clients have been bumped to version `v0.31.0`
* Regenerate API Clients from updated API models adding waiter utilities, and union parameters.
* `codegen`:
    * Add documentation to union API parameters describing valid member types, and usage example ([aws/smithy-go#239](https://github.com/aws/smithy-go/pull/239))
    * Normalize Metadata header map keys to be lower case ([aws/smithy-go#241](https://github.com/aws/smithy-go/pull/241)), ([#982](https://github.com/aws/aws-sdk-go-v2/pull/982))
        * Fixes [#376](https://github.com/aws/aws-sdk-go-v2/issues/376) Amazon S3 Metadata parameters keys are always returned as lower case.
    * Fix API client deserialization of XML based responses ([aws/smithy-go#245](https://github.com/aws/smithy-go/pull/245)), ([#992](https://github.com/aws/aws-sdk-go-v2/pull/992))
        * Fixes [#910](https://github.com/aws/aws-sdk-go-v2/issues/910)
* `service/s3`, `service/s3control`:
    * Add support for reading `s3_use_arn_region` from shared config file ([#991](https://github.com/aws/aws-sdk-go-v2/pull/991))
    * Add Utility for getting RequestID and HostID of response ([#983](https://github.com/aws/aws-sdk-go-v2/pull/983))


## Other changes
* Updates branch `HEAD` points from `master` to `main`.
    * This should not impact your application, but if you have pull requests or forks of the SDK you may need to update the upstream branch your fork is based off of.

## Migrating from v2 preview SDK's v0.30.0 to v0.31.0 release candidate

### smithy-go module relocation

If your application uses `smithy-go` utilities for request pipeline your application will need to be updated to refer to the new import path of `github.com/aws/smithy-go`. If you application did *not* use `smithy-go` utilities directly, your application will update automatically.

### EC2 IMDS module relocation

If your application used the `ec2imds` module, it has been relocated to `feature/ec2/imds`. Your application will need to update to the new import path, `github.com/aws/aws-sdk-go-v2/feature/ec2/imds`.

### CredentialsCache Constructor and ExpiryWindow Options

The `aws#CredentialsCache` type was updated, and a new constructor function, `NewCredentialsCache` was added. This function needs to be used to initialize the `CredentialCache`. The constructor also has function options to specify additional configuration, e.g. ExpiryWindow and Jitter.

If your application was specifying the `ExpiryWindow` with the `credentials/stscreds#AssumeRoleOptions`, `credentials/stscreds#WebIdentityRoleOptions`, `credentials/processcreds#Options`, or `credentials/ec2rolecrds#Options` types the `ExpiryWindow` option will need to specified on the `CredentialsCache` constructor instead.

### AWS Sigv4 Signer Refactor

The `aws/signer/v4` package's `Signer.SignHTTP` and `Signer.PresignHTTP` methods were updated to take functional options. If your application provided a custom implementation for API client's `HTTPSignerV4` or `HTTPPresignerV4` interfaces, that implementation will need to be updated for the new function signature.

### Configuration Loading

The `config#LoadDefaultConfig` function has been updated to require a `context.Context` as the first parameter, with additional optional function options as variadic additional arguments. Your application will need to update its usage of `LoadDefaultConfig` to pass in `context.Context` as the first parameter. If your application used the `With...` helpers those should continue to work without issue.

The v2 SDK corrects its behavior to be inline with the AWS CLI and other AWS SDKs. Refer to https://docs.aws.amazon.com/credref/latest/refdocs/overview.html for more information how to use the shared config and credentials files.


# Release 2020-11-30

## Breaking Change
* `codegen`: Add support for slice and maps generated with value members instead of pointer ([#887](https://github.com/aws/aws-sdk-go-v2/pull/887))
    * This update allow the SDK's code generation to be aware of API shapes and members that are not nullable, and can be rendered as value types by the code generation instead of pointer types.
    * Several API client parameter types will change from pointer members to value members for slice, map, number and bool member types.
    * See Migration notes for migrating to v0.30.0 with this change.
* `aws/transport/http`: Move aws.BuildableHTTPClient to HTTP transport package ([#898](https://github.com/aws/aws-sdk-go-v2/pull/898))
    * Moves the `BuildableHTTPClient` from the SDK's `aws` package to the `aws/transport/http` package as `BuildableClient` to with other HTTP specific utilities.
* `feature/cloudfront/sign`: Add CloudFront sign feature as module ([#884](https://github.com/aws/aws-sdk-go-v2/pull/884))
    * Moves `service/cloudfront/sign` package out of the `cloudfront` module, and into its own module as `github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign`.

## New Features
* `config`: Add a WithRetryer provider helper to the config loader ([#897](https://github.com/aws/aws-sdk-go-v2/pull/897))
    * Adds a `WithRetryer` configuration provider to the config loader as a convenience helper to set the `Retryer` on the `aws.Config` when its being loaded.
* `config`: Default to TLS 1.2 for HTTPS requests ([#892](https://github.com/aws/aws-sdk-go-v2/pull/892))
    * Updates the SDK's default HTTP client to use TLS 1.2 as the minimum TLS version for all HTTPS requests by default.

## Bug Fixes
* `config`: Fix AWS_CA_BUNDLE usage while loading default config ([#912](https://github.com/aws/aws-sdk-go-v2/pull/))
    * Fixes the `LoadDefaultConfig`'s configuration provider order to correctly load a custom HTTP client prior to configuring the client for `AWS_CA_BUNDLE` environment variable.
* `service/s3`: Fix signature mismatch error for s3 ([#913](https://github.com/aws/aws-sdk-go-v2/pull/913))
    * Fixes ([#883](https://github.com/aws/aws-sdk-go-v2/issues/883))
* `service/s3control`:
    * Fix HostPrefix addition behavior for s3control ([#882](https://github.com/aws/aws-sdk-go-v2/pull/882))
        * Fixes ([#863](https://github.com/aws/aws-sdk-go-v2/issues/863))
    * Fix s3control error deserializer ([#875](https://github.com/aws/aws-sdk-go-v2/pull/875))
        * Fixes ([#864](https://github.com/aws/aws-sdk-go-v2/issues/864))

## Service Client Highlights
* Pagination support has been added to supported APIs. See [Using Operation Paginators](https://aws.github.io/aws-sdk-go-v2/docs/making-requests/#using-operation-paginators) in the Developer Guide. ([#885](https://github.com/aws/aws-sdk-go-v2/pull/885))
* Logging support has been added to service clients. See [Logging](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/logging/) in the Developer Guide. ([#872](https://github.com/aws/aws-sdk-go-v2/pull/872))
* `service`: Add support for pre-signed URL clients for S3, RDS, EC2 service ([#888](https://github.com/aws/aws-sdk-go-v2/pull/888))
    * `service/s3`: operations `PutObject` and `GetObject` are now supported with s3 pre-signed url client.
    * `service/ec2`: operation `CopySnapshot` is now supported with ec2 pre-signed url client.
    * `service/rds`: operations `CopyDBSnapshot`, `CreateDBInstanceReadReplica`, `CopyDBClusterSnapshot`, `CreateDBCluster` are now supported with rds pre-signed url client.
* `service/s3`: Add support for S3 access point and S3 on outposts access point ARNs ([#870](https://github.com/aws/aws-sdk-go-v2/pull/870))
* `service/s3control`: Adds support for S3 on outposts access point and S3 on outposts bucket ARNs ([#870](https://github.com/aws/aws-sdk-go-v2/pull/870))

## Migrating from v2 preview SDK's v0.29.0 to v0.30.0

### aws.BuildableHTTPClient move
The `aws`'s `BuildableHTTPClient` HTTP client implementation was moved to `aws/transport/http` as `BuildableClient`. If your application used the `aws.BuildableHTTPClient` type, update it to use the `BuildableClient` in the `aws/transport/http` package.

### Slice and Map API member types
This release includes several code generation updates for API client's slice map members. Using API modeling metadata the Slice and map members are now generated as value types instead of pointer types. For your application this means that for these types, the SDK no longer will have pointer member types, and have value member types.

To migrate to this change you'll need to remove the pointer handling for slice and map members, and instead use value type handling of the member values.

### Boolean and Number API member types
Similar to the slice and map API member types being generated as value, the SDK's code generation now has metadata where the SDK can generate boolean and number members as value type instead of pointer types.

To migrate to this change you'll need to remove the pointer handling for numbers and boolean member types, and instead use value handling.

# Release 2020-10-30

## New Features
* Adds HostnameImmutable flag on aws.Endpoint to direct SDK if the associated endpoint is modifiable.([#848](https://github.com/aws/aws-sdk-go-v2/pull/848))

## Bug Fixes
* Fix SDK handling of xml based services - xml namespaces ([#858](https://github.com/aws/aws-sdk-go-v2/pull/858))
  * Fixes ([#850](https://github.com/aws/aws-sdk-go-v2/issues/850))

## Service Client Highlights
* API Clients have been bumped to version `v0.29.0`
    * Regenerate API Clients from update API models.
* Improve client doc generation.

## Core SDK Highlights
* Dependency Update: Updated SDK dependencies to their latest versions.

## Migrating from v2 preview SDK's v0.28.0 to v0.29.0
* API Clients ResolverOptions type renamed to EndpointResolverOptions

# Release 2020-10-26

## New Features
* `service/s3`: Add support for Accelerate, and Dualstack ([#836](https://github.com/aws/aws-sdk-go-v2/pull/836))
* `service/s3control`: Add support for Dualstack ([#836](https://github.com/aws/aws-sdk-go-v2/pull/836))

## Service Client Highlights
* API Clients have been bumped to version `v0.28.0`
    * Regenerate API Clients from update API models.
* `service/s3`: Add support for Accelerate, and Dualstack ([#836](https://github.com/aws/aws-sdk-go-v2/pull/836))
* `service/s3control`: Add support for Dualstack ([#836](https://github.com/aws/aws-sdk-go-v2/pull/836))
* `service/route53`: Fix sanitizeURL customization to handle leading slash(`/`) [#846](https://github.com/aws/aws-sdk-go-v2/pull/846)
    * Fixes [#843](https://github.com/aws/aws-sdk-go-v2/issues/843)
* `service/route53`: Fix codegen to correctly look for operations that need sanitize url ([#851](https://github.com/aws/aws-sdk-go-v2/pull/851))

## Core SDK Highlights
* `aws/protocol/restjson`: Fix unexpected JSON error response deserialization ([#837](https://github.com/aws/aws-sdk-go-v2/pull/837))
    * Fixes [#832](https://github.com/aws/aws-sdk-go-v2/issues/832)
* `example/service/s3/listobjects`: Add example for Amazon S3 ListObjectsV2 ([#838](https://github.com/aws/aws-sdk-go-v2/pull/838))

# Release 2020-10-16

## New Features
* `feature/s3/manager`:
  * Initial `v0.1.0` release
  * Add the Amazon S3 Upload and Download transfer manager ([#802](https://github.com/aws/aws-sdk-go-v2/pull/802))

## Service Client Highlights
* Clients have been bumped to version `v0.27.0`
* `service/machinelearning`: Add customization for setting client endpoint with PredictEndpoint value if set ([#782](https://github.com/aws/aws-sdk-go-v2/pull/782))
* `service/s3`: Fix empty response body deserialization in case of error response ([#801](https://github.com/aws/aws-sdk-go-v2/pull/801))
  * Fixes xml deserialization util to correctly handle empty response body in case of an error response.
* `service/s3`: Add customization to auto fill Content-Md5 request header for Amazon S3 operations ([#812](https://github.com/aws/aws-sdk-go-v2/pull/812))
* `service/s3`: Add fallback to using HTTP status code for error code ([#818](https://github.com/aws/aws-sdk-go-v2/pull/818))
  * Adds falling back to using the HTTP status code to create a API Error code when not error code is received from the service, such as HeadObject.
* `service/route53`: Add support for deserialzing `InvalidChangeBatch` API error ([#792](https://github.com/aws/aws-sdk-go-v2/pull/792))
* `codegen`: Remove API client `Options` getter methods ([#788](https://github.com/aws/aws-sdk-go-v2/pull/788))
* `codegen`: Regenerate API Client modeled endpoints ([#791](https://github.com/aws/aws-sdk-go-v2/pull/791))
* `codegen`: Sort API Client struct member paramaters by required and alphabetical ([#787](https://github.com/aws/aws-sdk-go-v2/pull/787))
* `codegen`: Add package docs to API client modules ([#821](https://github.com/aws/aws-sdk-go-v2/pull/821))
* `codegen`: Rename `smithy-go`'s `smithy.OperationError` to `smithy.OperationInvokeError`.

## Core SDK Highlights
* `config`:
  * Bumped to `v0.2.0`
  * Refactor Config Module, Add Config Package Documentation and Examples, Improve Overall SDK Readme ([#822](https://github.com/aws/aws-sdk-go-v2/pull/822))
* `credentials`:
  * Bumped to `v0.1.2`
  * Strip Monotonic Clock Readings when Comparing Credential Expiry Time ([#789](https://github.com/aws/aws-sdk-go-v2/pull/789))
* `ec2imds`:
  * Bumped to `v0.1.2`
  * Fix refreshing API token if expired ([#789](https://github.com/aws/aws-sdk-go-v2/pull/789))

## Migrating from v0.26.0 to v0.27.0

#### Configuration

The `config` module's exported types were trimmed down to add clarity and reduce confusion. Additional changes to the `config` module' helpers.

* Refactored `WithCredentialsProvider`, `WithHTTPClient`, and `WithEndpointResolver` to functions instead of structs.
* Removed `MFATokenFuncProvider`, use `AssumeRoleCredentialOptionsProvider` for setting options for `stscreds.AssumeRoleOptions`.
* Renamed `WithWebIdentityCredentialProviderOptions` to `WithWebIdentityRoleCredentialOptions`
* Renamed `AssumeRoleCredentialProviderOptions` to `AssumeRoleCredentialOptionsProvider`
* Renamed `EndpointResolverFuncProvider` to `EndpointResolverProvider`

#### API Client
* API Client `Options` type getter methods have been removed. Use the struct members instead.
* The error returned by API Client operations was renamed from `smithy.OperationError` to `smithy.OperationInvokeError`.

# Release 2020-09-30

## Service Client Highlights
* Service clients have been bumped to `v0.26.0` simplify the documentation experience when using [pkg.go.dev](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2).
* `service/s3`: Disable automatic decompression of getting Amazon S3 objects with the `Content-Encoding: gzip` metadata header. ([#748](https://github.com/aws/aws-sdk-go-v2/pull/748))
  * This changes the SDK's default behavior with regard to making S3 API calls. The client will no longer automatically set the `Accept-Encoding` HTTP request header, nor will it automatically decompress the gzipped response when the `Content-Encoding: gzip` response header was received.
  * If you'd like the client to sent the `Accept-Encoding: gzip` request header, you can add this header to the API operation method call with the [SetHeaderValue](https://pkg.go.dev/github.com/awslabs/smithy-go/transport/http#SetHeaderValue). middleware helper.
* `service/cloudfront/sign`: Fix cloudfront example usage of SignWithPolicy ([#673](https://github.com/aws/aws-sdk-go-v2/pull/673))
  * Fixes [#671](https://github.com/aws/aws-sdk-go-v2/issues/671) documentation typo by correcting the usage of `SignWithPolicy`.

## Core SDK Highlights
* SDK core module released at `v0.26.0`
* `config` module released at `v0.1.1`
* `credentials` module released at `v0.1.1`
* `ec2imds` module released at `v0.1.1`


# Release 2020-09-28
## Announcements
We’re happy to share the updated clients for the v0.25.0 preview version of the AWS SDK for Go V2.

The updated clients leverage new developments and advancements within AWS and the Go software ecosystem at large since
our original preview announcement. Using the new clients will be a bit different than before. The key differences are:
simplified API operation invocation, performance improvements, support for error wrapping, and a new middleware architecture.
So below we have a guided walkthrough to help try it out and share your feedback in order to better influence the features
you’d like to see in the GA version.

See [Announcement Blog Post](https://aws.amazon.com/blogs/developer/client-updates-in-the-preview-version-of-the-aws-sdk-for-go-v2/) for more details.

## Service Client Highlights
* Initial service clients released at version `v0.1.0`
## Core SDK Highlights
* SDK core module released at `v0.25.0`
* `config` module released at `v0.1.0`
* `credentials` module released at `v0.1.0`
* `ec2imds` module released at `v0.1.0`

## Migrating from v2 preview SDK's v0.24.0 to v0.25.0

#### Design changes

The v2 preview SDK `v0.25.0` release represents a significant stepping stone bringing the v2 SDK closer to its target design and usability. This release includes significant breaking changes to the v2 preview SDK. The updates in the `v0.25.0` release focus on refactoring and modularization of the SDK’s API clients to use the new [client design](https://github.com/aws/aws-sdk-go-v2/issues/438), updated request pipeline (aka [middleware](https://pkg.go.dev/github.com/awslabs/smithy-go/middleware)), refactored [credential providers](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials), and [configuration loading](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config) packages.

We've also bumped the minimum supported Go version with this release. Starting with v0.25.0 the SDK requires a minimum version of Go `v1.15`.

As a part of the refactoring done to v2 preview SDK some components have not been included in this update. The following is a non exhaustive list of features that are not available.

* API Paginators - [#439](https://github.com/aws/aws-sdk-go-v2/issues/439)
* API Waiters - [#442](https://github.com/aws/aws-sdk-go-v2/issues/442)
* Presign URL - [#794](https://github.com/aws/aws-sdk-go-v2/issues/794)
* Amazon S3 Upload and Download manager - [#802](https://github.com/aws/aws-sdk-go-v2/pull/802)
* Amazon DynamoDB's AttributeValue marshaler, and Expression package - [#790](https://github.com/aws/aws-sdk-go-v2/issues/790)
* Debug Logging - [#594](https://github.com/aws/aws-sdk-go-v2/issues/594)

We expect additional breaking changes to the v2 preview SDK in the coming releases. We expect these changes to focus on organizational, naming, and hardening the SDK's design for future feature capabilities after it is released for general availability.


#### Relocated Packages

In this release packages within the SDK were relocated, and in some cases those packages were converted to Go modules. The following is a list of packages have were relocated.

* `github.com/aws/aws-sdk-go-v2/aws/external` => `github.com/aws/aws-sdk-go-v2/config` module
* `github.com/aws/aws-sdk-go-v2/aws/ec2metadata` => `github.com/aws/aws-sdk-go-v2/ec2imds` module

The `github.com/aws/aws-sdk-go-v2/credentials` module contains refactored credentials providers.

* `github.com/aws/aws-sdk-go-v2/ec2rolecreds` => `github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds`
* `github.com/aws/aws-sdk-go-v2/endpointcreds` => `github.com/aws/aws-sdk-go-v2/credentials/endpointcreds`
* `github.com/aws/aws-sdk-go-v2/processcreds` => `github.com/aws/aws-sdk-go-v2/credentials/processcreds`
* `github.com/aws/aws-sdk-go-v2/stscreds` => `github.com/aws/aws-sdk-go-v2/credentials/stscreds`


#### Modularization

New modules were added to the v2 preview SDK to allow the components to be versioned independently from each other. This allows your application to depend on specific versions of an API client module, and take discrete updates from the SDK core and other API client modules as desired.

* [github.com/aws/aws-sdk-go-v2/config](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config)
* [github.com/aws/aws-sdk-go-v2/credentials](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials)
* Module for each API client, e.g. [github.com/aws/aws-sdk-go-v2/service/s3](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3)


#### API Clients

The following is a list of the major changes to the API client modules

* Removed paginators: we plan to add these back once they are implemented to integrate with the SDK's new API client design.
* Removed waiters: we need to further investigate how the V2 SDK should expose waiters, and how their behavior should be modeled.
* API Clients are now Go modules. When migrating to the v2 preview SDK `v0.25.0`, you'll need to add the API client's module to your application's go.mod file.
* API parameter nested types have been moved to a `types` package within the API client's module, e.g. `github.com/aws/aws-sdk-go-v2/service/s3/types` These types were moved to improve documentation and discovery of the API client, operation, and input/output types. For example Amazon S3's ListObject's operation [ListObjectOutput.Contents](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3/#ListObjectsOutput) input parameter is a slice of [types.Object](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3/types#Object).
* The client operation method has been renamed, removing the `Request` suffix. The method now invokes the operation instead of constructing a request, which needed to be invoked separately. The operation methods were also expanded to include functional options for providing operation specific configuration, such as modifying the request pipeline.

```go
result, err := client.Scan(context.TODO(), &dynamodb.ScanInput{
    TableName: aws.String("exampleTable"),
}, func(o *Options) {
    // Limit operation calls to only 1 attempt.
    o.Retryer = retry.AddWithMaxAttempts(o.Retryer, 1)
})
```


#### Configuration

In addition to the `github.com/aws/aws-sdk-go-v2/aws/external` package being made a module at `github.com/aws/aws-sdk-go-v2/config`, the `LoadDefaultAWSConfig` function was renamed to `LoadDefaultConfig`.

The `github.com/aws/aws-sdk-go-v2/aws/defaults` package has been removed. Its components have been migrated to the `github.com/aws/aws-sdk-go-v2/aws` package, and `github.com/aws/aws-sdk-go-v2/config` module.


#### Error Handling

The `github.com/aws/aws-sdk-go-v2/aws/awserr` package was removed as a part of the SDK error handling refactor. The SDK now uses typed errors built around [Go v1.13](https://golang.org/doc/go1.13#error_wrapping)'s [errors.As](https://pkg.go.dev/errors#As) and [errors.Unwrap](https://pkg.go.dev/errors#Unwrap) features. All SDK error types that wrap other errors implement the `Unwrap` method. Generic v2 preview SDK errors created with `fmt.Errorf` use `%w` to wrap the underlying error.

The SDK API clients now include generated public error types for errors modeled for an API. The SDK will automatically deserialize the error response from the API into the appropriate error type. Your application should use `errors.As` to check if the returned error matches one it is interested in. Your application can also use the generic interface [smithy.APIError](https://pkg.go.dev/github.com/awslabs/smithy-go/#APIError) to test if the API client's operation method returned an API error, but not check against a specific error.

API client errors returned to the caller will use error wrapping to layer the error values. This allows underlying error types to be specific to their use case, and the SDK's more generic error types to wrap the underlying error.

For example, if an [Amazon DynamoDB](https://aws.amazon.com/dynamodb/) [Scan](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/dynamodb#Scan) operation call cannot find the `TableName` requested, the error returned will contain [dynamodb.ResourceNotFoundException](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/dynamodb/types#ResourceNotFoundException). The SDK will return this error value wrapped in a couple layers, with each layer adding additional contextual information such as [ResponseError](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/transport/http#ResponseError) for AWS HTTP response error metadata , and [smithy.OperationError](https://pkg.go.dev/github.com/awslabs/smithy-go/#OperationError) for API operation call metadata.

```go
result, err := client.Scan(context.TODO(), params)
if err != nil {
    // To get a specific API error
    var notFoundErr *types.ResourceNotFoundException
    if errors.As(err, &notFoundErr) {
        log.Printf("scan failed because the table was not found, %v",
            notFoundErr.ErrorMessage())
    }

    // To get any API error
    var apiErr smithy.APIError
    if errors.As(err, &apiErr) {
        log.Printf("scan failed because of an API error, Code: %v, Message: %v",
            apiErr.ErrorCode(), apiErr.ErrorMessage())
    }

    // To get the AWS response metadata, such as RequestID
    var respErr *awshttp.ResponseError // Using import alias "awshttp" for package github.com/aws/aws-sdk-go-v2/aws/transport/http
    if errors.As(err, &respErr) {
        log.Printf("scan failed with HTTP status code %v, Request ID %v and error %v",
            respErr.HTTPStatusCode(), respErr.ServiceRequestID(), respErr)
    }

    return err
}
```

Logging an error value will include information from each wrapped error. For example, the following is a mock error logged for a Scan operation call that failed because the table was not found.

> 2020/10/15 16:03:37 operation error DynamoDB: Scan, https response error StatusCode: 400, RequestID: ABCREQUESTID123, ResourceNotFoundException: Requested resource not found


#### Endpoints

The `github.com/aws/aws-sdk-go-v2/aws/endpoints` has been removed from the SDK, along with all exported endpoint definitions and iteration behavior. Each generated API client now includes its own endpoint definition internally to the module.

API clients can optionally be configured with a generic [aws.EndpointResolver](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#EndpointResolver) via the [aws.Config.EndpointResolver](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#Config.EndpointResolver). If the API client is not configured with a custom endpoint resolver it will defer to the endpoint resolver the client module was generated with.
