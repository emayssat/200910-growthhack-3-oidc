IAM_POLICY_NAME?= oidc-federation-test-policy
IAM_POLICY_DOCUMENT_FILEPATH?= ./policy.json

IAM_POLICY_ARN?= arn:aws:iam::529733180916:policy/$(IAM_POLICY_NAME)

show_policy:
	aws iam get-policy --policy-arn $(IAM_POLICY_ARN)

create_policy:
	aws iam create-policy --policy-name $(IAM_POLICY_NAME) --policy-document file://$(IAM_POLICY_DOCUMENT_FILEPATH)

view_policies:
	aws iam list-policies
