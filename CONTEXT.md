# RustCtrl

RustCtrl is an IT team's workspace for monitoring and controlling a fleet of Windows computers and Android TVs on the office network.

## Language

**Device**:
A Windows computer or Android TV recorded in the fleet inventory. Its identity remains the same when its network address changes.
_Avoid_: IP address as device identity

**Fleet**:
All Devices managed by the IT team through RustCtrl.
_Avoid_: IP list

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
