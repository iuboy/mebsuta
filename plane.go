// 平面路由:按目的地分流日志。顶层选项构建默认链(业务面);UsePlane
// 为命名平面构建独立链;Plane 返回绑定平面的 logger。路由规则与
// handler 组装见 buildHandler 与 docs/SPEC.md「平面」。
package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
)

// PlaneKey 是平面路由标记属性的键。标记作为普通 attribute 保留在
// 输出中,供下游按面过滤。
const PlaneKey = "plane"

// 内置平面名。PlaneBusiness 是未标记记录的目的地,由顶层选项声明,
// 不可用于 UsePlane。
const (
	PlaneBusiness   = "business"
	PlaneManagement = "management"
	PlaneAudit      = "audit"
)

// PlaneAttr 返回标记平面的路由属性。
func PlaneAttr(name string) slog.Attr { return slog.String(PlaneKey, name) }

// Plane 返回绑定到 name 平面的 logger,从 slog.Default() 派生。
// default handler 不是平面路由器时,平面标记退化为普通属性。
func Plane(name string) *slog.Logger { return slog.Default().With(PlaneAttr(name)) }

// planeRouter 按平面标记与记录级别路由到独立链。优先级:
//
//  1. 显式平面标记(With(PlaneAttr(name)) 预设属性)→ 该平面链;
//     未配置的平面名 → 默认链
//  2. 级别 ≥ LevelAudit 且已配置审计面 → 审计面链(独占)
//  3. 其余 → 默认链
type planeRouter struct {
	handlerCore
	def    slog.Handler            // 默认链(业务面)
	planes map[string]slog.Handler // 已配置平面,不含默认链
	// fanout 是默认链 + 全部平面链的 *safeMulti;walk(CloseAll/
	// SetLevel/SetFileMaxAge/双重缓冲检测)经 unwrapHandler 穿透。
	fanout slog.Handler
}

func (h *planeRouter) Enabled(ctx context.Context, level slog.Level) bool {
	return h.def.Enabled(ctx, level)
}

func (h *planeRouter) Handle(ctx context.Context, r slog.Record) error {
	if ph, ok := h.planes[PlaneAudit]; ok && r.Level >= LevelAudit {
		return ph.Handle(ctx, r)
	}
	return h.def.Handle(ctx, r)
}

// WithAttrs 实现 slog.Handler。含平面标记时返回固定绑定该平面的视图;
// 否则返回保留 LevelAudit 隐式路由的视图,预设属性同时应用到默认链与
// 审计链——两条链都可能服务该视图的记录。
func (h *planeRouter) WithAttrs(attrs []slog.Attr) slog.Handler {
	if name := planeNameOf(attrs); name != "" {
		return &boundPlane{router: h, chain: applyView(h.planeOf(name), attrs, nil)}
	}
	return &boundPlane{
		router: h,
		chain:  applyView(h.def, attrs, nil),
		audit:  applyView(h.planes[PlaneAudit], attrs, nil),
	}
}

// WithGroup 实现 slog.Handler。
func (h *planeRouter) WithGroup(name string) slog.Handler {
	// slog:WithGroup("") 是 no-op——与 AttrsSub/GroupSub/contractJSONHandler
	// 的先例一致。
	if name == "" {
		return h
	}
	return &boundPlane{
		router: h,
		chain:  h.def.WithGroup(name),
		audit:  applyView(h.planes[PlaneAudit], nil, &name),
	}
}

func (h *planeRouter) unwrapHandler() slog.Handler { return h.fanout }

// planeOf 返回 name 平面链;未配置的平面名降级到默认链。
func (h *planeRouter) planeOf(name string) slog.Handler {
	if ph, ok := h.planes[name]; ok {
		return ph
	}
	return h.def
}

// boundPlane 是路由器的 With/WithGroup 派生视图。chain 为本视图的主链;
// audit 非 nil 时(未显式标记平面)LevelAudit 记录路由到同样带本视图
// 预设的审计链视图。
type boundPlane struct {
	router *planeRouter
	chain  slog.Handler
	audit  slog.Handler // nil = 固定平面绑定或未配置审计面
}

func (b *boundPlane) Enabled(ctx context.Context, level slog.Level) bool {
	return b.serve(level).Enabled(ctx, level)
}

func (b *boundPlane) Handle(ctx context.Context, r slog.Record) error {
	return b.serve(r.Level).Handle(ctx, r)
}

func (b *boundPlane) serve(level slog.Level) slog.Handler {
	if b.audit != nil && level >= LevelAudit {
		return b.audit
	}
	return b.chain
}

func (b *boundPlane) WithAttrs(attrs []slog.Attr) slog.Handler {
	// 后到的平面标记:重新绑定到对应平面链。已应用到本视图 chain 的
	// 预设不随迁——平面绑定应是 logger 的第一个 With(Plane() 正是
	// 如此);此路径仅为防御非常规使用顺序。
	if name := planeNameOf(attrs); name != "" {
		return &boundPlane{router: b.router, chain: applyView(b.router.planeOf(name), attrs, nil)}
	}
	return &boundPlane{
		router: b.router,
		chain:  b.chain.WithAttrs(attrs),
		audit:  withView(b.audit, attrs, nil),
	}
}

func (b *boundPlane) WithGroup(name string) slog.Handler {
	// slog:WithGroup("") 是 no-op。
	if name == "" {
		return b
	}
	return &boundPlane{
		router: b.router,
		chain:  b.chain.WithGroup(name),
		audit:  withView(b.audit, nil, &name),
	}
}

func (b *boundPlane) unwrapHandler() slog.Handler { return b.router }

// applyView 把预设属性与 group 应用到 h 后返回(h 为 nil 时返回 nil,
// 表示该目的地不存在)。
func applyView(h slog.Handler, attrs []slog.Attr, group *string) slog.Handler {
	if h == nil {
		return nil
	}
	if len(attrs) > 0 {
		h = h.WithAttrs(attrs)
	}
	if group != nil && *group != "" {
		h = h.WithGroup(*group)
	}
	return h
}

// withView 在既有视图之上继续应用预设;h 为 nil 时保持 nil。
func withView(h slog.Handler, attrs []slog.Attr, group *string) slog.Handler {
	if h == nil {
		return nil
	}
	return applyView(h, attrs, group)
}

// planeNameOf 返回 attrs 中首个平面标记的平面名;无标记或值非字符串
// 时返回空串。
func planeNameOf(attrs []slog.Attr) string {
	for _, a := range attrs {
		if a.Key != PlaneKey {
			continue
		}
		if s, ok := a.Value.Resolve().Any().(string); ok {
			return s
		}
		return ""
	}
	return ""
}

// UsePlane 声明一个输出平面:name 命名的独立 handler 链由 opts 构建。
// 顶层选项声明默认链(业务面);UsePlane 不可嵌套,PlaneBusiness 不可
// 用于 UsePlane。至少一个 UsePlane 时 New/Init 返回的 handler 为平面
// 路由器。
func UsePlane(name string, opts ...HandlerOption) HandlerOption {
	return func(o *handlerOptions) error {
		if name == "" {
			return &ConfigError{Field: "UsePlane", Msg: "plane name cannot be empty"}
		}
		if name == PlaneBusiness {
			return &ConfigError{Field: "UsePlane", Msg: fmt.Sprintf("plane %q is the default chain; declare its handlers at top level", name)}
		}
		for _, p := range o.planes {
			if p.name == name {
				return &ConfigError{Field: "UsePlane", Msg: fmt.Sprintf("duplicate plane %q", name)}
			}
		}
		sub := &handlerOptions{}
		for _, opt := range opts {
			if err := opt(sub); err != nil {
				return err
			}
		}
		if len(sub.planes) > 0 {
			return &ConfigError{Field: "UsePlane", Msg: "UsePlane cannot be nested"}
		}
		o.planes = append(o.planes, planeOption{name: name, opts: sub})
		return nil
	}
}

var (
	_ slog.Handler     = (*planeRouter)(nil)
	_ slog.Handler     = (*boundPlane)(nil)
	_ handlerUnwrapper = (*planeRouter)(nil)
	_ handlerUnwrapper = (*boundPlane)(nil)
)
