from ecpy.curves import Point, Curve

cv = Curve.get_curve("secp256k1")

MY_PK = Point(0x7d29a75d7745c317aee84f38d0bddbf7eb1c91b7dcf45eab28d6d31584e00dd0, 0x25bb44e5ab9501e784a6f31a93c30cd6ad5b323f669b0af0ca52b8c5aa6258b9, cv)    
BERTRAND_PK = Point(0x206aeb643e2fe72452ef6929049d09496d7252a87e9daf6bf2e58914b55f3a90, 0x46c220ee7cbe03b138a76dcb4db673c35e2ab81b4235486fe4dbd2ad093e8df4, cv)
CHARLES_PK = Point(0xab44fe53836d50fa4b5755aa0683b5a61726e508a1ca814a93e1eab7122abdea, 0x4cbd1496aa36fc016bfe7b12c9fb8bb78eacab6f3655c586604250bb870cdaf1, cv)
DANIEL_PK = Point(0xb1c1e7545483dce5567345a7cf12d1c0a6bcbd0637b81f4082453a9bd89bd701, 0xb01d4cadf75b8ce3e05eda73a81a7c5cfb67618950e60657d61d4a44d2115dc7, cv)