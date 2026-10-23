# RustCtrl

RustCtrl is an IT team's workspace for monitoring and controlling a fleet of Windows computers and Android TVs on the office network.

## Language

**Device**:
A Windows computer or Android TV recorded in the fleet inventory. Its identity remains the same when its network address changes.
_Avoid_: IP address as device identity

**Fleet**:
All Devices managed by the IT team through RustCtrl.
_Avoid_: IP list

**Fleet Inventory**:
RustCtrl's operational list of Devices and the information needed to identify and access them. It is independent of the office's separate asset inventory application.
_Avoid_: asset register, external inventory mirror

**Controller**:
The staff application for accessing the Fleet and performing actions allowed by the staff member's role.
_Avoid_: Server, Agent

**Dashboard**:
The view within the Controller that summarizes the Fleet inventory and status.
_Avoid_: Controller when referring to a single view

**Server**:
The shared authority for staff accounts, inventory, Remote Sessions, Management Tasks, and activity history.
_Avoid_: Controller

**Agent**:
The RustCtrl component representing a Windows Device in the Fleet.
_Avoid_: Controller

**Staff Account**:
An individual IT staff member's identity in RustCtrl, with an Admin or Operator role. It is distinct from a component's connection identity.
_Avoid_: shared account, Controller certificate as staff identity

**Staff Session**:
A revocable period of access to RustCtrl through the Controller under a Staff Account. It is distinct from a Remote Session with a Device.
_Avoid_: Remote Session, Agent connection

**Agent Installation Package**:
A deployment-specific package containing the configuration and installation authorization needed for an Agent to join its intended RustCtrl Server automatically. Each installed Device has its own identity.
_Avoid_: shared Device identity, staff login credentials

**Installation Authorization**:
An Admin-granted permission for new Agents to join a specific RustCtrl Server through an Agent Installation Package. It is distinct from an already enrolled Device's permission to connect.
_Avoid_: Device credentials, Staff Session

**Inventory Cleanup**:
An Admin's removal of an offline Device entry from the Fleet Inventory without revoking its Agent's access. A still-authorized Agent can restore the entry by connecting again.
_Avoid_: Device Block, uninstall

**Device Block**:
An Admin-imposed restriction on a Device identity that denies operational Agent access while keeping the Device visible in the Fleet Inventory.
_Avoid_: Inventory Cleanup, Installation Authorization revocation

**Admin**:
A staff member allowed to manage accounts, Devices, configuration, and Management Tasks, as well as open Remote Sessions.
_Avoid_: shared account

**Operator**:
A staff member allowed to monitor the Fleet and open Remote Sessions using an individual account.
_Avoid_: endpoint user

**Remote Session**:
A period during which one staff member can view and control a Device's screen. A Device has at most one controlling staff member at a time.
_Avoid_: Task, agent connection

**Management Task**:
A management action submitted by an Admin for one or more Devices, with a separate outcome for each Device.
_Avoid_: Remote Session

**Provisioning**:
The initial preparation that establishes a Device's identity and access within RustCtrl.
_Avoid_: per-session approval
