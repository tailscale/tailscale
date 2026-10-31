package tailcfg

import "testing"

func TestDERPRegionCanServeDERP(t *testing.T) {
	tests := []struct {
		name string
		region *DERPRegion
		want bool
	}{
		{
			name:   "nil_region",
			region: (*DERPRegion)(nil),
			want:   false,
		},
		{
			name:   "no_nodes",
			region: &DERPRegion{},
			want:   false,
		},
		{
			name: "stun_only",
			region: &DERPRegion{
				Nodes: []*DERPNode{
					{Name: "1a", STUNOnly: true},
					{Name: "1b", STUNOnly: true},
				},
			},
			want: false,
		},
		{
			name: "mixed",
			region: &DERPRegion{
				Nodes: []*DERPNode{
					{Name: "1a", STUNOnly: true},
					{Name: "1b"},
				},
			},
			want: true,
		},
		{
			name: "derp_only",
			region: &DERPRegion{
				Nodes: []*DERPNode{{Name: "1a"}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.region.CanServeDERP(); got != tt.want {
				t.Errorf("CanServeDERP() = %v, want %v", got, tt.want)
			}
			var v DERPRegionView
			if tt.region != nil {
				v = tt.region.View()
			}
			if got := v.CanServeDERP(); got != tt.want {
				t.Errorf("DERPRegionView.CanServeDERP() = %v, want %v", got, tt.want)
			}
		})
	}
}
