// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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

package schema

import (
	"cmp"
	"fmt"
	"math/big"

	"github.com/go-viper/mapstructure/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// EnumRequirement specifies an enumerated value in the node tree and the corresponding value to set.
type EnumRequirement struct {
	// PathSegments is the list of enum path segments.
	PathSegments []string
	// Value is the enum value.
	Value string
}

// NodeMetadata contains node metadata.
type NodeMetadata struct {
	Type       string `yaml:"fieldType,omitempty"`
	IsBindOnly bool   `yaml:"isBindOnly,omitempty"`
}

// A Node represents a single schema element.
type Node struct {
	// Name is the name of the node.
	Name string `yaml:"name"`
	// Descriptions is the list of node's descriptions. A node can have multiple descriptions if it is the result of the
	// merging of multiple nodes.
	Descriptions []string `yaml:"descriptions,omitempty"`
	// JSONTypes is the node's optional list of JSON types.
	JSONTypes []string `yaml:"types,omitempty"`
	// Required is true if the user is required to provide the current node in order to completely describe the
	// containing node.
	Required bool `yaml:"required,omitempty"`
	// Minimum is the minimum supported integer value (it can be different from nil only if JSONTypes contains the
	// integer type).
	Minimum *float64 `yaml:"minimum,omitempty"`
	// MinLength is the minimum string value length (it can be different from nil only if JSONTypes contains the string
	// type).
	MinLength *int `yaml:"minLength,omitempty"`
	// MinItems is the minimum number of node items (it can be different from nil only if JSONTypes contains the array
	// type).
	MinItems *int `yaml:"minItems,omitempty"`
	// MinProperties is the minimum number of properties the node can contain (it can be different from nil only if
	// JSONTypes contains the object type).
	MinProperties *int `yaml:"minProperties,omitempty"`
	// Pattern is the regular expression the node is constrained to adhere (it can be different from nil only if
	// JSONTypes contains the string type).
	Pattern *string `yaml:"pattern,omitempty"`
	// Default is the node's optional default value.
	Default *any `yaml:"default,omitempty"`
	// Examples is the node's optional list of examples.
	Examples []any `yaml:"examples,omitempty"`
	// Enum is the node's optional list of enumerated values that are allowed to be set as node's value. It is only
	// populated if the node represents an enumerated value.
	Enum []any `yaml:"enum,omitempty"`
	// Children is the node's optional list of child nodes (a.k.a node's fields).
	Children []*Node `yaml:"fields,omitempty"`
	// PseudoChildren is the node's optional list of pseudo child nodes (a.k.a node's exposed fields).
	PseudoChildren []*Node `yaml:"exposedFields,omitempty"`
	// Pseudo is true if the node is "pseudo" node. In the context of a node tree, a pseudo node is a node not present
	// in the original schema: it is added to augment the schema with additional information, such as node's additional
	// exposed fields.
	Pseudo bool `yaml:"-"`
	// Metadata are the node's metadata.
	Metadata *NodeMetadata `yaml:",inline"`
}

// mergeMetadataSchema merges the provided metadata schema in the current node.
func (n *Node) mergeMetadataSchema(metadataSchema *jsonschema.Schema) error {
	parsedMetadata, err := parseMetadata(metadataSchema)
	if err != nil {
		return fmt.Errorf("error parsing metadata: %w", err)
	}

	n.mergeMetadata(parsedMetadata)
	return nil
}

type fieldMetadata struct {
	Type              string                    `mapstructure:"fieldType"`
	Description       string                    `mapstructure:"description"`
	IsBindOnly        bool                      `mapstructure:"bindOnly"`
	SubFieldsMetadata map[string]*fieldMetadata `mapstructure:"fields"`
}

type metadata struct {
	Type                   string                    `mapstructure:"type"`
	ExistingFieldsMetadata map[string]*fieldMetadata `mapstructure:"existingFields"`
	NewFieldsMetadata      map[string]*fieldMetadata `mapstructure:"newFields"`
}

// parseMetadata parses and the returns the metadata represented by the provided schema.
func parseMetadata(metadataSchema *jsonschema.Schema) (*metadata, error) {
	md := &metadata{}
	if err := mapstructure.Decode(*metadataSchema.Default, md); err != nil {
		return nil, err
	}

	return md, nil
}

// mergeMetadata merges the provided metadata information in the provided node.
func (n *Node) mergeMetadata(md *metadata) {
	n.mergeExistingFieldsMetadata(md.ExistingFieldsMetadata)
	n.mergeNewFieldsMetadata(md.NewFieldsMetadata)
}

// mergeExistingFieldsMetadata associates the provided fields metadata to the corresponding fields in the hierarchy
// starting from the provided node.
func (n *Node) mergeExistingFieldsMetadata(fieldsMetadata map[string]*fieldMetadata) {
	if len(fieldsMetadata) == 0 {
		return
	}

	for _, child := range n.Children {
		for fieldName, fieldMd := range fieldsMetadata {
			if child.Name != fieldName {
				continue
			}

			nodeMetadata := newNodeMetadata(fieldMd)
			child.Metadata = nodeMetadata
			child.mergeExistingFieldsMetadata(fieldMd.SubFieldsMetadata)
		}
	}
}

// newNodeMetadata creates a new NodeMetadata object from the provided field metadata.
func newNodeMetadata(fieldMd *fieldMetadata) *NodeMetadata {
	return &NodeMetadata{
		Type:       fieldMd.Type,
		IsBindOnly: fieldMd.IsBindOnly,
	}
}

// mergeNewFieldsMetadata creates, under the current node, a new pseudo nodes hierarchy reflecting the provided fields
// metadata hierarchy.
func (n *Node) mergeNewFieldsMetadata(fieldsMetadata map[string]*fieldMetadata) {
	for fieldName, fieldMd := range fieldsMetadata {
		newNode := newPseudoNode(fieldName, fieldMd)
		newNode.mergeNewFieldsMetadata(fieldMd.SubFieldsMetadata)
		n.PseudoChildren = append(n.PseudoChildren, newNode)
	}
}

// newPseudoNode creates a new pseudo node with the provided name by leveraging the provided field metadata.
func newPseudoNode(name string, fieldMd *fieldMetadata) *Node {
	var descriptions []string
	if fieldMd.Description != "" {
		descriptions = append(descriptions, fieldMd.Description)
	}
	node := &Node{
		Name:         name,
		Descriptions: descriptions,
		Pseudo:       true,
		Metadata:     newNodeMetadata(fieldMd),
	}
	return node
}

// mergeSubSchema merges the provided sub-schema in the current node.
func (n *Node) mergeSubSchema(subSchema *jsonschema.Schema, requirements []*EnumRequirement) error {
	subSchemaNode, err := extractNode(subSchema, "", false, requirements)
	if err != nil {
		return fmt.Errorf("error extracting sub-schema node: %w", err)
	}

	n.mergeNode(subSchemaNode)
	return nil
}

// mergeNode merges the provided node into the current node.
func (n *Node) mergeNode(node *Node) {
	n.Descriptions = append(n.Descriptions, node.Descriptions...)
	n.JSONTypes = append(n.JSONTypes, node.JSONTypes...)
	n.Required = n.Required || node.Required
	n.Minimum = getMax(n.Minimum, node.Minimum)
	n.MinLength = getMax(n.MinLength, node.MinLength)
	n.MinItems = getMax(n.MinItems, node.MinItems)
	n.MinProperties = getMax(n.MinProperties, node.MinProperties)
	if n.Pattern == nil {
		n.Pattern = node.Pattern
	}
	if n.Default == nil {
		n.Default = node.Default
	}
	n.Examples = append(n.Examples, node.Examples...)
	n.Children = append(n.Children, node.Children...)
	n.PseudoChildren = append(n.PseudoChildren, node.PseudoChildren...)
	if n.Metadata == nil {
		n.Metadata = node.Metadata
	}
}

// getMax returns the pointer containing the greater value. If one of the two provided pointer is nil, it returns the
// other pointer.
func getMax[T cmp.Ordered](a, b *T) *T {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a > *b {
		return a
	}
	return b
}

// pruneChildren prunes the node tree starting at the current node by removing all nodes not encountered along the
// provided path. (1) Pseudo nodes and (2) first-level children of the last node in the provide path are kept in the
// resulting node tree.
func (n *Node) pruneChildren(nodePath []string) error {
	if len(nodePath) == 0 {
		// Leave children of the last node untouched but prune their children.
		children := n.Children
		if len(children) == 0 {
			return nil
		}

		for _, child := range children {
			child.Children = nil
		}
		return nil
	}

	// Retrieve the current node's child with the next name from the node path.
	name := nodePath[0]
	child := n.getChild(name)
	if child == nil {
		return fmt.Errorf("cannot find %q", name)
	}

	// Recursively prune children of the selected child.
	if err := child.pruneChildren(nodePath[1:]); err != nil {
		return err
	}

	// Reduce the node list to the selected child + the list of pseudo nodes.
	pseudoChildren := n.getPseudoChildrenExcept(name)
	children := []*Node{child}
	children = append(children, pseudoChildren...)
	n.Children = children
	return nil
}

// findChild finds and returns the child node with the provided name. If the child is not found, it returns nil.
func (n *Node) getChild(name string) *Node {
	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}

	return nil
}

// getPseudoChildrenExcept returns the list of pseudo children, except the ones having the provided name.
func (n *Node) getPseudoChildrenExcept(name string) []*Node {
	var children []*Node
	for _, child := range n.Children {
		if child.Pseudo && child.Name != name {
			children = append(children, child)
		}
	}
	return children
}

// rootNodeName is the root node name.
const rootNodeName = "<root>"

// Describe returns a node tree describing the fields along the path described by the provided node path. The provided
// requirements are used to set values for nodes representing enumerated values (this can be used to "unlock" node tree
// paths enabled only if specific values are provided for the aforementioned nodes).
func Describe(nodePath []string, requirements []*EnumRequirement) (*Node, error) {
	schema, err := load()
	if err != nil {
		return nil, fmt.Errorf("error loading schema: %w", err)
	}

	root, err := extractNode(schema, rootNodeName, true, requirements)
	if err != nil {
		return nil, fmt.Errorf("error extracting node tree: %w", err)
	}
	printNode("", root)

	if err := root.pruneChildren(nodePath); err != nil {
		return nil, fmt.Errorf("error pruning node tree: %w", err)
	}
	printNode("", root)

	return root, nil
}

func printNode(space string, n *Node) {
	if n == nil {
		return
	}

	fmt.Printf("%s%s\n", space, n.Name)
	for _, child := range n.Children {
		printNode(space+"   ", child)
	}
}

const metadataPropName = "x-metadata"

// extractNode is the main node tree extraction function. It recursively calls itself to build the node tree
// representing the provided schema.
func extractNode(schema *jsonschema.Schema, name string, required bool,
	requirements []*EnumRequirement) (*Node, error) {
	// Initialize a new node from the current schema.
	node := newNode(schema, name, required)

	// Merge information from any schema reference using the "ref" keyword.
	if ref := schema.Ref; ref != nil {
		var refNode *Node
		// Do not merge information from field binding schema other than its pattern value.
		if ref.ID == bindingSchemaURL {
			refNode = &Node{Pattern: getPattern(ref.Pattern)}
		} else {
			refNode = newNode(ref, "", false)
		}
		node.mergeNode(refNode)
	}

	// Extract the first applicable enum requirement and creates the new list of requirements to be propagated.
	firstRequirement, newRequirements := evaluateNewEnumRequirements(requirements)

	// Extract the current node's children.
	var err error
	node.Children, err = extractChildren(schema, newRequirements)
	if err != nil {
		return nil, fmt.Errorf("error extracting %q node's children: %w", name, err)
	}

	// Merge metadata, if present.
	// NOTICE: metadata must be merged after extracting children.
	if metadata, ok := schema.Properties[metadataPropName]; ok {
		if err := node.mergeMetadataSchema(metadata); err != nil {
			return nil, fmt.Errorf("error merging metadata schema: %w", err)
		}
	}

	if firstRequirement == nil {
		return node, nil
	}

	// Retrieve the sub-schema corresponding to the first applicable enum requirement and merge it if it is found.
	key, value := firstRequirement.PathSegments[0], firstRequirement.Value
	subSchema := getSubSchema(schema, key, value)
	if subSchema == nil {
		return node, nil
	}

	if err := node.mergeSubSchema(subSchema, newRequirements); err != nil {
		return nil, fmt.Errorf("error merging sub-schema for (key: %s, value: %s): %w", key, value, err)
	}

	return node, nil
}

// newNode creates a new node from the data extracted from given schema.
func newNode(schema *jsonschema.Schema, name string, required bool) *Node {
	var descriptions []string
	if description := schema.Description; description != "" {
		descriptions = []string{description}
	}

	var types []string
	if schema.Types != nil {
		types = schema.Types.ToStrings()
	}

	var enum []any
	if schema.Enum != nil {
		enum = schema.Enum.Values
	}

	return &Node{
		Name:          name,
		Descriptions:  descriptions,
		JSONTypes:     types,
		Required:      required,
		Minimum:       rationalToFloat64(schema.Minimum),
		MinLength:     schema.MinLength,
		MinItems:      schema.MinItems,
		MinProperties: schema.MinProperties,
		Pattern:       getPattern(schema.Pattern),
		Default:       schema.Default,
		Examples:      schema.Examples,
		Enum:          enum,
	}
}

// getPattern converts a jsonschema.Regexp into a string and returns its pointer. It returns nil if the provided pattern
// is nil.
func getPattern(pattern jsonschema.Regexp) *string {
	if pattern == nil {
		return nil
	}

	p := pattern.String()
	return &p
}

// rationalToFloat64 converts a big.Rat value into the nearest float64 value and returns its pointer.
func rationalToFloat64(rat *big.Rat) *float64 {
	if rat == nil {
		return nil
	}

	f, _ := rat.Float64()
	return &f
}

// evaluateNewEnumRequirements returns the first applicable enum requirement (the first one with an enum path just
// composed by one segment) and the new updated list of remaining requirements.
func evaluateNewEnumRequirements(
	requirements []*EnumRequirement) (firstRequirement *EnumRequirement, newRequirements []*EnumRequirement) {
	for _, requirement := range requirements {
		segments, value := requirement.PathSegments, requirement.Value
		if len(segments) != 1 {
			newRequirements = append(newRequirements, &EnumRequirement{
				PathSegments: segments[1:],
				Value:        requirement.Value,
			})
			continue
		}

		if firstRequirement == nil {
			firstRequirement = requirement
		} else {
			newRequirements = append(newRequirements, &EnumRequirement{PathSegments: segments, Value: value})
		}
	}

	return firstRequirement, newRequirements
}

// extractChildren extracts the list of nodes corresponding to the provided schema's properties.
func extractChildren(schema *jsonschema.Schema, requirements []*EnumRequirement) ([]*Node, error) {
	properties := getProperties(schema)
	propertyNum := len(properties)
	if propertyNum == 0 {
		return nil, nil
	}

	nodes := make([]*Node, 0, propertyNum)
	for prop, propSchema := range properties {
		// Skip the property representing node metadata.
		if prop == metadataPropName {
			continue
		}

		// Generate new nodes for the property and its children.
		required := isPropertyRequired(schema, prop)
		node, err := extractNode(propSchema, prop, required, requirements)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, node)
	}
	return nodes, nil
}

// getProperties returns the merged nested and non-nested lists of schemas associated to the "properties" keyword. This
// includes the properties directly available under the provided schema, or the properties accessible from "ref",
// "items" and "items.ref" schemas.
func getProperties(schema *jsonschema.Schema) map[string]*jsonschema.Schema {
	properties := make(map[string]*jsonschema.Schema)
	addProperties(properties, schema.Properties)
	if ref := schema.Ref; ref != nil {
		addProperties(properties, ref.Properties)
	}
	if items2020 := schema.Items2020; items2020 != nil {
		addProperties(properties, getProperties(items2020))
	}
	return properties
}

// addProperties add the provided source properties to the destination properties.
func addProperties(dstProperties, srcProperties map[string]*jsonschema.Schema) {
	for prop, propSchema := range srcProperties {
		dstProperties[prop] = propSchema
	}
}

// isPropertyRequired returns true if the property with the provided name is required in the provided containing schema.
func isPropertyRequired(schema *jsonschema.Schema, prop string) bool {
	for _, req := range schema.Required {
		if prop == req {
			return true
		}
	}

	return false
}

// getSubSchema returns the sub-schema of the provided schema corresponding to the provided key-value couple, if
// present; otherwise it returns nil. The returned sub-schema is the "then" schema corresponding to the "if" schema
// requiring the provided value for the provided key (i.e: property).
func getSubSchema(schema *jsonschema.Schema, subSchemaKey, subSchemaValue string) *jsonschema.Schema {
	for _, allOfSchema := range getAllOf(schema) {
		p, ok := allOfSchema.If.Properties[subSchemaKey]
		if !ok {
			continue
		}

		c := p.Const
		if c == nil {
			continue
		}

		if s, ok := (*c).(string); ok && s == subSchemaValue {
			return allOfSchema.Then.Ref
		}
	}
	return nil
}

// getAllOf returns the merged nested and non-nested lists of schemas associated to the "allOf" keyword. This includes
// the "allOf" schemas directly available under the provided schema, or the ones accessible from "ref", "items" and
// "items.ref" schemas.
func getAllOf(schema *jsonschema.Schema) []*jsonschema.Schema {
	var allOf []*jsonschema.Schema
	allOf = append(allOf, schema.AllOf...)
	if ref := schema.Ref; ref != nil {
		allOf = append(allOf, ref.AllOf...)
	}
	if items2020 := schema.Items2020; items2020 != nil {
		allOf = append(allOf, getAllOf(items2020)...)
	}
	return allOf
}
